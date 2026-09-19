/**
 * The demo server behind `npm run demo:web`: the partner portal, and the gateway it drives.
 *
 *     npx tsx scripts/demo-web.ts        (PORT=8788, GATEWAY_PORT=8791; both overridable)
 *
 * What it boots:
 *
 *   1. The `@stellaronramp/gateway-http` server on loopback, with every seam injected: the BBS+
 *      issuer key, the status-list signer, the session store, the session-JWT issuer, and the
 *      applicant creator of the in-process mock KYC provider (`scripts/demo/mock-kyc.ts`).
 *   2. The public server: the landing page, the partner portal and its `/api/*` routes
 *      (`scripts/onboard/`), the browser copy of the Stellar SDK, plus a standalone `/demo` page
 *      that runs the same pipeline for an anonymous throwaway wallet.
 *
 * A portal run (`scripts/demo/demo-flow.ts`) opens a real session on the gateway, records the
 * mock provider's verdict, issues a real BBS+ credential, derives a proof, and submits
 * `attest_bbs` to Stellar testnet from the deployer account.
 *
 * Durable state lives in the data directory (`PORTAL_DATA_DIR`, default `scripts/.demo-data/`):
 * accounts, hashed sign-in sessions, holder-side credentials, the revocation-index counter and
 * the status list. Runs and the gateway's own session store are per-process.
 *
 * Environment: `PORT`, `GATEWAY_PORT`, `STELLARONRAMP_DEPLOYER_SECRET` (else the stellar CLI
 * alias `STELLAR_ALIAS`), `PORTAL_DATA_DIR`, `PORTAL_RP_ID` (WebAuthn relying-party id for the
 * wallet), `PORTAL_ALLOW_NO_SIGNER=1` (boot without a funded signer; the on-chain half is
 * disabled).
 */

import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, statSync } from 'node:fs';
import { createServer } from 'node:http';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { dirname, extname, join, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

import { Keypair } from '@stellar/stellar-sdk';

import type { DemoDeps, EmitStep } from './demo/demo-flow.js';
import { JsonFileAccountStore, PortalSessionStore } from './onboard/accounts.js';
import { InMemoryRunRegistry } from './onboard/kyc-run.js';
import { handlePortalApi } from './onboard/portal-api.js';
import type { PortalApiDeps } from './onboard/portal-api.js';

/* -------------------------------------------------------------------------- */
/* Paths, ports, and the one assertion helper                                  */
/* -------------------------------------------------------------------------- */

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, '..');
const WEB_ROOT = join(ROOT, 'apps', 'web');
/** The UMD browser build of the pinned @stellar/stellar-sdk (global `StellarSdk`). */

const STELLAR_SDK_BROWSER_BUNDLE = join(
  ROOT,
  'node_modules',
  '@stellar',
  'stellar-sdk',
  'dist',
  'stellar-sdk.min.js',
);

const DATA_DIR = resolve(process.env['PORTAL_DATA_DIR'] ?? join(ROOT, 'scripts', '.demo-data'));
const ACCOUNTS_FILE = join(DATA_DIR, 'accounts.json');
const ALLOW_NO_SIGNER = process.env['PORTAL_ALLOW_NO_SIGNER'] === '1';

class DeployerKeyUnavailableError extends Error {
  override readonly name = 'DeployerKeyUnavailableError';
}

const GATEWAY_PORT = Number(process.env['GATEWAY_PORT'] ?? 8791);
const PORT = Number(process.env['PORT'] ?? 8788);
const DEPLOYER_ALIAS = process.env['STELLAR_ALIAS'] ?? 'stellaronramp-dev';

function must(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(`[demo-web] ${message}`);
}

/* -------------------------------------------------------------------------- */
/* 1. Workspace builds                                                         */
/* -------------------------------------------------------------------------- */

/** Build any workspace whose `dist/` is missing, so a fresh clone runs on the first try. */
function selfHeal(): void {
  const builds: Array<[string, string]> = [
    ['packages/identity', 'packages/identity/dist/index.js'],
    ['packages/gateway', 'packages/gateway/dist/index.js'],
    ['apps/gateway-http', 'apps/gateway-http/dist/server.js'],
    ['packages/sdk', 'packages/sdk/dist/index.js'],
  ];
  for (const [workspace, distPath] of builds) {
    if (existsSync(join(ROOT, distPath))) continue;
    console.log(`[demo-web] building ${workspace} (dist missing)…`);
    execFileSync('npm', ['run', 'build', '-w', workspace], { cwd: ROOT, stdio: 'inherit' });
  }
}

/* -------------------------------------------------------------------------- */
/* 2. deployments.json + the deployer key                                      */
/* -------------------------------------------------------------------------- */

interface TestnetDeployments {
  networkPassphrase: string;
  deployer: string;
  networkConfig: { rpcUrl: string };
  contracts: Record<string, { id?: string } | undefined>;
}

function readDeployments(): TestnetDeployments {
  const raw = JSON.parse(readFileSync(join(ROOT, 'deployments.json'), 'utf8')) as {
    testnet?: TestnetDeployments;
  };
  must(raw.testnet !== undefined, 'deployments.json has no testnet section');
  return raw.testnet;
}

/**
 * The account that pays for attestations. `STELLARONRAMP_DEPLOYER_SECRET` when set (hosted
 * deployments), else the stellar CLI keystore. Either way the key must be the deployer
 * `deployments.json` names, and the secret is never logged.
 */
function readDeployerKeypair(expectedPublicKey: string): Keypair {
  let secret: string;
  let source: string;
  const fromEnv = process.env['STELLARONRAMP_DEPLOYER_SECRET'];
  if (fromEnv !== undefined && fromEnv.trim().length > 0) {
    secret = fromEnv.trim();
    source = 'STELLARONRAMP_DEPLOYER_SECRET';
  } else {
    source = `the stellar CLI alias "${DEPLOYER_ALIAS}"`;
    try {
      secret = execFileSync('stellar', ['keys', 'show', DEPLOYER_ALIAS], { encoding: 'utf8' }).trim();
    } catch (cause) {
      throw new DeployerKeyUnavailableError(
        `could not run "stellar keys show ${DEPLOYER_ALIAS}": ${String((cause as Error)?.message ?? cause)}. ` +
          'The demo pays for attestations with that identity: install the stellar CLI and add the ' +
          `funded key, set STELLAR_ALIAS to an alias that resolves to ${expectedPublicKey}, or pass ` +
          'the secret as STELLARONRAMP_DEPLOYER_SECRET.',
        { cause },
      );
    }
  }
  const kp = Keypair.fromSecret(secret);
  must(
    kp.publicKey() === expectedPublicKey,
    `${source} resolves to ${kp.publicKey()}, but deployments.json records ${expectedPublicKey} ` +
      'as the testnet deployer',
  );
  return kp;
}

/* -------------------------------------------------------------------------- */
/* 3. Statics                                                                  */
/* -------------------------------------------------------------------------- */

const WEB_MIME: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.txt': 'text/plain; charset=utf-8',
};

function respondText(res: ServerResponse, status: number, text: string): void {
  res.writeHead(status, {
    'content-type': 'text/plain; charset=utf-8',
    'content-length': String(Buffer.byteLength(text)),
  });
  res.end(text);
}

function serveFile(res: ServerResponse, path: string, contentType: string): void {
  let body: Buffer;
  try {
    body = readFileSync(path);
  } catch {
    respondText(res, 404, 'not found');
    return;
  }
  res.writeHead(200, {
    'content-type': contentType,
    'content-length': String(body.byteLength),
    'cache-control': 'no-cache',
  });
  res.end(body);
}

function serveStatic(res: ServerResponse, pathname: string): void {
  let relativePath: string;
  if (pathname === '/' || pathname === '') relativePath = 'index.html';
  else if (pathname === '/portal' || pathname === '/portal/') relativePath = 'portal.html';
  else if (pathname === '/demo' || pathname === '/demo/') relativePath = 'demo.html';
  else relativePath = pathname.replace(/^\/+/, '');

  if (relativePath.includes('\0')) {
    respondText(res, 404, 'not found');
    return;
  }
  const resolvedPath = resolve(WEB_ROOT, relativePath);
  if (resolvedPath !== WEB_ROOT && !resolvedPath.startsWith(WEB_ROOT + sep)) {
    respondText(res, 404, 'not found');
    return;
  }

  let body: Buffer;
  try {
    if (!statSync(resolvedPath).isFile()) {
      respondText(res, 404, 'not found');
      return;
    }
    body = readFileSync(resolvedPath);
  } catch {
    respondText(res, 404, 'not found');
    return;
  }
  res.writeHead(200, {
    'content-type': WEB_MIME[extname(resolvedPath).toLowerCase()] ?? 'application/octet-stream',
    'content-length': String(body.byteLength),
    'cache-control': 'no-cache',
  });
  res.end(body);
}

/* -------------------------------------------------------------------------- */
/* 4. The public server                                                        */
/* -------------------------------------------------------------------------- */

/** What `/demo/run` calls: one anonymous run, emitting steps as it goes. */
type DemoRunner = (outcome: 'approve' | 'reject', emit: EmitStep) => Promise<unknown>;

/** Drive one anonymous run for the `/demo` page and stream its steps as server-sent events. */
async function handleDemoRun(res: ServerResponse, url: URL, demo: DemoRunner): Promise<void> {
  const outcome = url.searchParams.get('outcome') === 'reject' ? 'reject' : 'approve';
  res.writeHead(200, {
    'content-type': 'text/event-stream',
    'cache-control': 'no-cache',
    connection: 'keep-alive',
    'x-accel-buffering': 'no',
  });
  res.flushHeaders();

  let closed = false;
  res.on('close', () => {
    closed = true;
  });
  const write = (chunk: string): void => {
    if (closed) return;
    try {
      res.write(chunk);
    } catch {
      closed = true;
    }
  };

  try {
    await demo(outcome, (step) => write(`data: ${JSON.stringify(step)}\n\n`));
    write('event: done\ndata: {}\n\n');
  } catch (err) {
    const message = String((err as Error)?.message ?? err);
    console.error(`[demo-web] demo run (${outcome}) failed: ${message}`);
    write(`event: error\ndata: ${JSON.stringify({ message })}\n\n`);
  } finally {
    if (!closed) res.end();
  }
}

async function handleRequest(
  req: IncomingMessage,
  url: URL,
  method: string,
  res: ServerResponse,
  portal: PortalApiDeps,
  demo: DemoRunner,
): Promise<void> {
  const pathname = decodeURIComponent(url.pathname);

  // The browser's own copy of the Stellar SDK, so the portal can read the chain directly
  // (simulateTransaction against public testnet RPC) with this server out of the path.
  if (pathname === '/vendor/stellar-sdk.min.js') {
    if (method !== 'GET' && method !== 'HEAD') {
      respondText(res, 405, 'method not allowed');
      return;
    }
    serveFile(res, STELLAR_SDK_BROWSER_BUNDLE, 'text/javascript; charset=utf-8');
    return;
  }

  if (pathname === '/demo/run') {
    if (method !== 'GET') {
      respondText(res, 405, 'method not allowed');
      return;
    }
    await handleDemoRun(res, url, demo);
    return;
  }

  if (pathname === '/api' || pathname.startsWith('/api/')) {
    await handlePortalApi(req, res, url, portal);
    return;
  }

  if (method !== 'GET' && method !== 'HEAD') {
    respondText(res, 405, 'method not allowed');
    return;
  }
  serveStatic(res, pathname);
}

function startPublicServer(portal: PortalApiDeps, demo: DemoRunner): void {
  const server = createServer((req, res) => {
    let url: URL;
    try {
      url = new URL(req.url ?? '/', `http://127.0.0.1:${PORT}`);
    } catch {
      respondText(res, 400, 'bad request target');
      return;
    }
    const method = (req.method ?? 'GET').toUpperCase();
    void handleRequest(req, url, method, res, portal, demo).catch((err: unknown) => {
      console.error(`[demo-web] request ${method} ${url.pathname} failed:`, err);
      if (!res.headersSent) {
        respondText(res, 500, 'internal demo-server error');
      } else {
        try {
          res.end();
        } catch {
          /* response already gone */
        }
      }
    });
  });

  server.on('clientError', (_err, socket) => {
    socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
  });

  server.listen(PORT, '127.0.0.1', () => {
    console.log(`[demo-web] listening on http://127.0.0.1:${PORT}/ (portal at /portal)`);
    console.log(`[demo-web] internal gateway on http://127.0.0.1:${GATEWAY_PORT} (loopback only)`);
  });
}

/* -------------------------------------------------------------------------- */
/* 5. Boot                                                                     */
/* -------------------------------------------------------------------------- */

async function main(): Promise<void> {
  selfHeal();

  // Dynamic imports: everything below depends on `dist/`, which `selfHeal` may have just built.
  const { buildServer, InMemorySessionStore } = await import('@stellaronramp/gateway-http');
  const { generateEs256KeyPair, signJws } = await import('@stellaronramp/gateway');
  const { generateIssuerKeyPair } = await import('@stellaronramp/identity');
  const { createMockKyc } = await import('./demo/mock-kyc.js');
  const { runDemo, runOnboardingPipeline, readOnChainRecord } = await import('./demo/demo-flow.js');
  const { JsonFileCredentialStore, JsonFileRevocationIndexAllocator, JsonFileStatusListStore } =
    await import('./onboard/durable.js');
  const { portalWalletMinter } = await import('./onboard/wallet.js');

  const testnet = readDeployments();
  const networkPassphrase = testnet.networkPassphrase;
  const rpcUrl = testnet.networkConfig.rpcUrl;
  const gateContractId = testnet.contracts['kyc-gate']?.id;
  must(
    typeof gateContractId === 'string' && gateContractId.startsWith('C'),
    'no kyc-gate contract id in deployments.json: deploy the contracts first (see README)',
  );
  const registryContractId = testnet.contracts['kyc-registry']?.id;
  must(
    typeof registryContractId === 'string' && registryContractId.startsWith('C'),
    'no kyc-registry contract id in deployments.json: deploy the contracts first (see README)',
  );

  let deployerKp: Keypair;
  let chainEnabled = true;
  try {
    deployerKp = readDeployerKeypair(testnet.deployer);
  } catch (err) {
    if (!(err instanceof DeployerKeyUnavailableError) || !ALLOW_NO_SIGNER) throw err;
    deployerKp = Keypair.random();
    chainEnabled = false;
    console.warn(
      '[demo-web] PORTAL_ALLOW_NO_SIGNER=1: the on-chain half is disabled.\n' +
        '  Register, sign-in and the wizard work; POST /api/kyc/submit answers 503 chain_unavailable.',
    );
  }

  /* --- the gateway, with every seam injected ----------------------------- */

  // The demo issuer: a fixed seed, registered on kyc-registry at deployment. Public by design;
  // testnet only.
  const issuerKeys = await generateIssuerKeyPair(new Uint8Array(32).fill(7));
  const kyc = createMockKyc();
  const sessionStore = new InMemorySessionStore();

  const { privateKey: sessionJwtPrivateKey, publicKey: sessionJwtPublicKey } = generateEs256KeyPair();
  const SESSION_JWT_ISSUER = 'stellaronramp-demo';
  const SESSION_JWT_AUDIENCE = 'stellaronramp-demo';

  mkdirSync(DATA_DIR, { recursive: true });
  const revocationIndexes = new JsonFileRevocationIndexAllocator(join(DATA_DIR, 'revocation-index.json'));
  const credentials = new JsonFileCredentialStore(join(DATA_DIR, 'credentials.json'));
  const statusList = new JsonFileStatusListStore(join(DATA_DIR, 'status-list.json'));

  console.warn(
    '[demo-web] demo configuration:\n' +
      '  * The KYC provider is an in-process mock; its verdict is the scenario chosen in the wizard.\n' +
      '  * The BBS+ issuer secret derives from a fixed public seed. Testnet only.\n' +
      '  * Each portal account gets a passkey smart wallet deployed on testnet through the Channels\n' +
      '    relayer; the software authenticator key is discarded after deployment.\n' +
      '  * Both sockets bind 127.0.0.1. Attestations are paid by the deployer account.',
  );

  const gw = buildServer({
    network: 'testnet',
    networkPassphrase,
    kycGateContractId: gateContractId,
    kycRegistryContractId: registryContractId,
    issuerPublicKey: issuerKeys.publicKey,
    issuerSecretKey: issuerKeys.secretKey,
    // The status-list credential's id must be https; the list itself is served by this gateway at
    // GET /v1/status-list/{issuer_id} from the file-backed store.
    statusListUrl: 'https://status-list.stellaronramp.invalid/v1/status-list',
    statusListSigningKey: { seed: new Uint8Array(32).fill(0xa5) },
    verificationMethod: 'did:dev:stellaronramp-demo#key-1',
    statusListStore: statusList,
    sessionStore,
    revocationIndexAllocator: revocationIndexes,
    kycApplicantCreator: kyc.applicantCreator,
    now: () => Math.floor(Date.now() / 1000),
    sessionJwtIssuer: {
      async issue(claims) {
        return signJws({
          privateKey: sessionJwtPrivateKey,
          claims: {
            iss: SESSION_JWT_ISSUER,
            sub: claims.walletCAddr,
            aud: SESSION_JWT_AUDIENCE,
            iat: claims.issuedAt,
            nbf: claims.issuedAt,
            exp: claims.expiresAt,
          },
        });
      },
    },
    auth: {
      sessionJwt: {
        publicKey: sessionJwtPublicKey,
        issuer: SESSION_JWT_ISSUER,
        audience: SESSION_JWT_AUDIENCE,
      },
    },
  });

  await new Promise<void>((ready) => {
    gw.listen(GATEWAY_PORT, '127.0.0.1', () => ready());
  });

  /* --- the pipeline's dependencies -------------------------------------- */

  const deps: DemoDeps = {
    gatewayBaseUrl: `http://127.0.0.1:${GATEWAY_PORT}`,
    explorerBase: 'https://stellar.expert/explorer/testnet',
    networkPassphrase,
    gateContractId,
    registryContractId,
    rpcUrl,
    submitter: deployerKp,
    issuerPublicKey: issuerKeys.publicKey,
    issuerSecretKey: issuerKeys.secretKey,
    kyc,
    approveSession: (sessionId) => sessionStore.setStatus(sessionId, 'approved'),
    credentialStore: credentials,
    now: () => Math.floor(Date.now() / 1000),
  };

  /* --- the partner portal ------------------------------------------------ */

  const accounts = new JsonFileAccountStore(ACCOUNTS_FILE);
  const sessions = new PortalSessionStore({ file: join(DATA_DIR, 'sessions.json') });
  const runs = new InMemoryRunRegistry();
  const wallets = portalWalletMinter({
    rpcUrl,
    networkPassphrase,
    rpId: process.env['PORTAL_RP_ID'] ?? 'stellaronramp.local',
    relayerBaseUrl: 'https://channels.openzeppelin.com/testnet',
    explorerBase: deps.explorerBase,
  });
  console.log(
    `[demo-web] partner portal: ${accounts.size} account(s) in ${DATA_DIR}, ${sessions.size} live session(s), ` +
      `${credentials.size} stored credential(s), next revocation index ${revocationIndexes.next}\n` +
      `[demo-web] open http://127.0.0.1:${PORT}/portal` +
      (chainEnabled ? '' : '  (chain half disabled)'),
  );

  const portal: PortalApiDeps = {
    accounts,
    sessions,
    runs,
    runPipeline: (args) => runOnboardingPipeline(deps, args),
    readRecord: (cAddr) => readOnChainRecord(deps, cAddr),
    gateContractId,
    chain: { rpcUrl, networkPassphrase, simulationSource: testnet.deployer },
    createWallet: (args) => wallets.create(args),
    now: () => Math.floor(Date.now() / 1000),
    chainEnabled,
  };

  startPublicServer(portal, (outcome, emit) => runDemo(deps, { outcome, emit }));
}

main().catch((err: unknown) => {
  console.error(`[demo-web] fatal: ${String((err as Error)?.message ?? err)}`);
  process.exitCode = 1;
});
