import {
  InMemoryRevocationIndexAllocator,
  generateEs256KeyPair,
  verifyJws,
} from '@stellaronramp/gateway';
import { generateIssuerKeyPair } from '@stellaronramp/identity';

import { InMemorySessionStore } from '../src/seams/session-store.js';
import { Es256SessionJwtIssuer } from '../src/seams/session-jwt.js';
import { toHttpError } from '../src/errors.js';
import { writeError } from '../src/middleware.js';
import { InMemoryStatusListStore } from '../src/types.js';
import type { AppConfig, GatewayAuthConfig, RouteHandler } from '../src/types.js';

/** Run a handler the way the server dispatcher does: capture writes, map thrown errors. */
export async function runHandler(
  handler: RouteHandler,
  ctx: Omit<Parameters<RouteHandler>[0], 'response' | 'requestId'>,
): Promise<{ status: number; body: unknown; headers: Record<string, string> }> {
  const res: any = { statusCode: 0, headers: {}, body: '', setHeader: () => {}, end: () => {} };
  res.setHeader = (k: string, v: string) => { res.headers[k] = v; };
  res.end = (p: string) => { res.body = p; };
  const requestId = 'r1';
  try {
    await handler({ ...ctx, response: res, requestId });
  } catch (err) {
    writeError(res, toHttpError(err), requestId);
  }
  return { status: res.statusCode, body: res.body === '' ? null : JSON.parse(res.body), headers: res.headers };
}

export const VALID_WALLET_A = 'GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF';
export const VALID_WALLET_B = 'GAOS3CYFTRFSBSVN4GORA3PSOIJICMMHDCRRQEOQDS42ASC4V52BXPE3';
export const VALID_WALLET_C_ADDR = `C${'A'.repeat(55)}`;

export async function issuerKeys(): Promise<{ publicKey: Uint8Array; secretKey: Uint8Array }> {
  const seed = new Uint8Array(32);
  for (let i = 0; i < seed.length; i += 1) seed[i] = i;
  const kp = await generateIssuerKeyPair(seed);
  return { publicKey: kp.publicKey, secretKey: kp.secretKey };
}

export function makeSessionStore(): InMemorySessionStore {
  return new InMemorySessionStore();
}

export function makeApplicantCreator() {
  const seen: { walletCAddr: string; sessionId: string }[] = [];
  return {
    seen,
    async create(req: { walletCAddr: string; sessionId: string }): Promise<string> {
      seen.push({ walletCAddr: req.walletCAddr, sessionId: req.sessionId });
      return 'applicant-123';
    },
  };
}

export function makeSessionJwtIssuer() {
  return {
    async issue(): Promise<string> {
      return 'session-token-fake';
    },
  };
}

export const AUTH_ISSUER = 'https://gateway.test';
export const AUTH_AUDIENCE = 'gateway-session';

export function makeRealSessionJwt(): {
  issuer: Es256SessionJwtIssuer;
  sessionJwt: GatewayAuthConfig['sessionJwt'];
} {
  const { privateKey } = generateEs256KeyPair();
  const issuer = new Es256SessionJwtIssuer({
    signingKey: privateKey,
    issuer: AUTH_ISSUER,
    audience: AUTH_AUDIENCE,
  });
  const sessionJwt = {
    publicKey: issuer.verificationKey,
    issuer: issuer.issuer,
    audience: issuer.audience,
  };
  return { issuer, sessionJwt };
}

export function mintSessionToken(
  issuer: Es256SessionJwtIssuer,
  walletCAddr: string,
  nowSeconds: number,
): Promise<string> {
  return issuer.issue({
    sessionId: `sess-${walletCAddr.slice(0, 8)}`,
    walletCAddr,
    issuedAt: nowSeconds,
    expiresAt: nowSeconds + 900,
  });
}

export { verifyJws };

export async function bearerFor(config: AppConfig, walletCAddr: string): Promise<string> {
  const issuer = config.sessionJwtIssuer;
  if (!(issuer instanceof Es256SessionJwtIssuer)) {
    throw new Error('bearerFor: config does not carry a real Es256SessionJwtIssuer');
  }
  return mintSessionToken(issuer, walletCAddr, config.now());
}

export function fixedClock(nowSeconds: number): () => number {
  return () => nowSeconds;
}

export async function makeConfig(
  overrides: Partial<AppConfig> = {},
  opts: { nowSeconds?: number } = {},
): Promise<AppConfig> {
  const keys = await issuerKeys();
  const { issuer: sessionIssuer, sessionJwt } = makeRealSessionJwt();
  const base: AppConfig = {
    network: 'testnet',
    networkPassphrase: 'Test SDF Network ; September 2015',
    kycGateContractId: 'C0000000000000000000000000000000000000000000000000000000000000',
    kycRegistryContractId: 'R0000000000000000000000000000000000000000000000000000000000000',
    issuerPublicKey: keys.publicKey,
    issuerSecretKey: keys.secretKey,
    statusListUrl: 'https://issuer.example/v1/status-list',
    statusListSigningKey: { seed: new Uint8Array(32).fill(9) },
    verificationMethod: 'did:example:issuer#key-1',
    statusListStore: new InMemoryStatusListStore(),
    sessionStore: makeSessionStore(),
    revocationIndexAllocator: new InMemoryRevocationIndexAllocator(),
    now: fixedClock(opts.nowSeconds ?? 1_700_000_000),
    sessionJwtIssuer: sessionIssuer,
    kycApplicantCreator: makeApplicantCreator(),
    auth: { sessionJwt },
  };
  return { ...base, ...overrides };
}
