/**
 * The onboarding portal's HTTP API — the `/api/*` surface `apps/web/portal.html` drives.
 *
 * TRANSPORT ONLY, the same discipline as `apps/gateway-http`: this module parses a request, calls
 * a seam, and writes a response. Every rule that matters lives elsewhere — the account rules in
 * `./accounts.ts`, the pipeline in `../demo/demo-flow.ts`, the run buffering in `./kyc-run.ts`.
 *
 * WHY IT IS NOT IN `apps/gateway-http`. That server is the credential authority and deliberately
 * has no user model (see `./accounts.ts`). An email + password account belongs to the host
 * application hosting the portal, which is the dev server in `scripts/demo-web.ts`. Adding a user
 * table to the gateway would be the wrong layer, not merely the wrong file.
 *
 * THE SPLIT THAT MAKES PROGRESS WORK. `POST /api/kyc/submit` cannot itself stream: the wizard's
 * payload is a JSON body, and `EventSource` only issues GETs. So submit starts the run and answers
 * `202 {runId}`; the page then opens `GET /api/kyc/stream?runId=…` and receives the buffered +
 * live frames. See `./kyc-run.ts` for why the buffer is load-bearing.
 *
 * WHAT A RESPONSE MAY CONTAIN. Never a password, never a password hash, never the wizard's PII —
 * `toPublicAccount` trims the record and the pipeline's `DemoStep`s carry only booleans and hashes.
 * Errors answer the compact `{error:{code,message}}` envelope; the message is written for a human
 * and never echoes request material.
 */

import type { IncomingMessage, ServerResponse } from 'node:http';

import {
  JsonFileAccountStore,
  InvalidCredentialsError,
  PORTAL_COOKIE_NAME,
  PortalAccountError,
  PortalSessionStore,
  UnauthenticatedError,
  assertEmail,
  assertPassword,
  clearedPortalSessionCookie,
  portalSessionCookie,
  readCookies,
  toPublicAccount,
  type AccountRecord,
} from './accounts.js';
import type { InMemoryRunRegistry, RunEvent } from './kyc-run.js';
import { ONRAMP_MAX_TRY, ONRAMP_MIN_TRY } from './onramp.js';
import type { OnrampResult } from './onramp.js';
import type { EmitStep, OnboardingResult, OnChainRecordView } from '../demo/demo-flow.js';
import type { Applicant } from '../demo/mock-kyc.js';
import { DISCLOSABLE_CLAIM_NAMES } from '@stellaronramp/identity';
import type { DisclosableClaimName } from '@stellaronramp/identity';

/** Cap on an API request body. The wizard's payload is a few hundred bytes; this is generous. */
const MAX_BODY_BYTES = 256 * 1024;

/**
 * What the API needs. Every field is a seam so this module owns no wiring: the pipeline and the
 * chain read are handed in already bound to the demo's `DemoDeps`, and the wallet minter is a
 * function so the deployment mechanics (relayer, authenticator) stay with the caller.
 */
export interface PortalApiDeps {
  readonly accounts: JsonFileAccountStore;
  readonly sessions: PortalSessionStore;
  readonly runs: InMemoryRunRegistry<OnboardingResult>;
  /** On-ramp runs, kept apart from KYC runs so one cannot block the other. */
  readonly onrampRuns: InMemoryRunRegistry<OnrampResult>;
  /** Buy USDC with TRY through the anchor for a wallet the gate allows (scripts/onboard/onramp.ts). */
  readonly runOnramp: (args: { accountId: string; walletCAddr: string; tryAmount: number; emit: EmitStep }) => Promise<OnrampResult>;
  /** The funding account and its USDC balance, for the dashboard. */
  readonly readOnramp: (accountId: string) => Promise<{ fundingAccount: string | null; usdcBalance: string | null }>;
  /** Run the real onboarding pipeline (`runOnboardingPipeline`) for one wallet + scenario. */
  readonly runPipeline: (args: {
    cAddr: string;
    answer: 'GREEN' | 'RED';
    applicant: Applicant;
    disclose: readonly DisclosableClaimName[];
    emit: EmitStep;
  }) => Promise<OnboardingResult>;
  /** Read a wallet's on-chain record and the gate's verdicts (`readOnChainRecord`). */
  readonly readRecord: (cAddr: string) => Promise<OnChainRecordView>;
  /** The deployed kyc-gate id, so the page can print verify-it-yourself CLI commands. */
  readonly gateContractId: string;
  /** What the browser needs to simulate the gate's reads itself, bypassing this server. */
  readonly chain: { rpcUrl: string; networkPassphrase: string; simulationSource: string };
  /** Mark session cookies `Secure` (a hosted https deployment). Auto-detected from x-forwarded-proto too. */
  readonly secureCookies?: boolean;
  /** Cap on simultaneous KYC runs across ALL accounts — each one spends the deployer's testnet balance. Default 3. */
  readonly maxActiveRuns?: number;
  /**
   * Deploy the account's passkey smart wallet on testnet (scripts/onboard/wallet.ts). Called at
   * most ONCE per account, from inside the first KYC run, so the deployment streams as a step.
   */
  readonly createWallet: (args: { userName: string; emit: EmitStep }) => Promise<{
    address: string;
    keyId: string;
    deployTxHash: string;
  }>;
  readonly now: () => number;
  /**
   * Whether the chain half of the portal can run at all — i.e. whether a FUNDED signer was
   * available at boot. `false` only under the explicit `PORTAL_ALLOW_NO_SIGNER` dev escape hatch
   * (scripts/demo-web.ts), which exists so the account/KYC surface can be exercised on a machine
   * with no stellar CLI and no deployer key.
   *
   * WHEN FALSE, THE CHAIN PATHS REFUSE EARLY AND SAY WHY. `kyc/submit` answers 503
   * `chain_unavailable` rather than starting a 40-second run that dies inside the SDK, and
   * `kyc/record` returns an empty view. Nothing degrades silently: the flag is reported on every
   * account response so the UI can say so up front.
   */
  readonly chainEnabled: boolean;
}

/* -------------------------------------------------------------------------- */
/* Request / response helpers                                                  */
/* -------------------------------------------------------------------------- */

/* -------------------------------------------------------------------------- */
/* the wizard's applicant                                                      */
/* -------------------------------------------------------------------------- */

/** What the wizard ticks by default, and what an absent `disclose` means. */
const DEFAULT_DISCLOSURE: readonly DisclosableClaimName[] = ['over18', 'notSanctioned'];

/** The claims the contract's u32 bitmap has a bit for; the rest live only in the credential. */
const CHAIN_BACKED_CLAIMS: readonly DisclosableClaimName[] = [
  'over18',
  'over21',
  'notSanctioned',
  'jurisdictionOk',
];

const ISO_DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
const ALPHA2_RE = /^[A-Z]{2}$/;

/**
 * Validate the wizard's identity answers into the shape the mock provider "verifies". Strict on
 * purpose: a malformed date of birth would make `deriveClaimSet` throw deep inside the run with a
 * message about the provider, when the honest answer is a 400 here. Nothing parsed is persisted.
 */
function parseApplicant(raw: unknown): Applicant {
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new PortalAccountError(400, 'missing_field', 'missing "applicant"');
  }
  const bag = raw as Record<string, unknown>;
  const givenName = requireStringField(bag, 'firstName');
  const familyName = requireStringField(bag, 'lastName');
  const dateOfBirth = requireStringField(bag, 'dateOfBirth');
  const country = requireStringField(bag, 'country').toUpperCase();
  const documentNumber = requireStringField(bag, 'documentNumber');
  if (!ISO_DATE_RE.test(dateOfBirth) || Number.isNaN(Date.parse(`${dateOfBirth}T00:00:00Z`))) {
    throw new PortalAccountError(400, 'invalid_field', '"dateOfBirth" must be YYYY-MM-DD');
  }
  if (!ALPHA2_RE.test(country)) {
    throw new PortalAccountError(400, 'invalid_field', '"country" must be an ISO 3166-1 alpha-2 code');
  }
  // The run's PII scan hunts this exact value across the presentation; a 1–5 character value
  // would match random hex by chance and report a leak that is not one.
  if (documentNumber.length < 6) {
    throw new PortalAccountError(400, 'invalid_field', '"documentNumber" must be at least 6 characters');
  }
  return { givenName, familyName, dateOfBirth, documentNumber, residenceCountry: country };
}

/**
 * The claims the holder ticked. Only these are revealed by the proof, so only these can reach the
 * claim record. At least one must carry an on-chain bit, because `attest_bbs` refuses a record
 * with no claims at all and the honest place to say so is here, before a wallet is deployed.
 */
export function parseDisclosure(raw: unknown): readonly DisclosableClaimName[] {
  if (raw === undefined) return DEFAULT_DISCLOSURE;
  if (!Array.isArray(raw)) {
    throw new PortalAccountError(400, 'invalid_field', '"disclose" must be an array of claim names');
  }
  const names: DisclosableClaimName[] = [];
  for (const entry of raw) {
    if (typeof entry !== 'string' || !DISCLOSABLE_CLAIM_NAMES.includes(entry as DisclosableClaimName)) {
      throw new PortalAccountError(400, 'invalid_field', `"${String(entry)}" is not a disclosable claim`);
    }
    if (!names.includes(entry as DisclosableClaimName)) names.push(entry as DisclosableClaimName);
  }
  if (names.length === 0) {
    throw new PortalAccountError(400, 'invalid_field', 'choose at least one claim to disclose');
  }
  if (!names.some((n) => CHAIN_BACKED_CLAIMS.includes(n))) {
    throw new PortalAccountError(
      400,
      'invalid_field',
      `the claim record carries only ${CHAIN_BACKED_CLAIMS.join(', ')}, so at least one of those ` +
        'must be disclosed for the chain to record anything',
    );
  }
  return names;
}

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  if (res.headersSent) {
    if (!res.writableEnded) res.end();
    return;
  }
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': String(Buffer.byteLength(payload)),
    'cache-control': 'no-store',
  });
  res.end(payload);
}

/** Map any thrown value to the error envelope, refusing to write twice to a started response. */
function sendError(res: ServerResponse, err: unknown): void {
  if (res.headersSent) {
    if (!res.writableEnded) res.end();
    return;
  }
  if (err instanceof PortalAccountError) {
    // Code and status only — never the message (it may echo a field name) and never a body.
    console.warn(`[portal-api] ${err.status} ${err.code}`);
    sendJson(res, err.status, { error: { code: err.code, message: err.message } });
    return;
  }
  // An unexpected fault is logged for the operator and reported to the browser WITHOUT its text:
  // an internal message can name files and arguments, and this surface faces the public demo port.
  console.error('[portal-api] unexpected failure:', err);
  sendJson(res, 500, { error: { code: 'internal_error', message: 'internal server error' } });
}

/**
 * Read and parse a JSON object body, with a size cap. An empty body is `{}` rather than an error,
 * so a route with no fields still reads naturally.
 */
async function readJsonBody(req: IncomingMessage): Promise<Record<string, unknown>> {
  const declared = req.headers['content-length'];
  if (declared !== undefined) {
    const n = Number(declared);
    if (Number.isFinite(n) && n > MAX_BODY_BYTES) {
      throw new PortalAccountError(413, 'body_too_large', 'request body too large');
    }
  }
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of req) {
    const buf = chunk as Buffer;
    total += buf.length;
    if (total > MAX_BODY_BYTES) {
      throw new PortalAccountError(413, 'body_too_large', 'request body too large');
    }
    chunks.push(buf);
  }
  if (total === 0) return {};
  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    throw new PortalAccountError(400, 'invalid_json', 'request body is not valid JSON');
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new PortalAccountError(400, 'invalid_json', 'request body must be a JSON object');
  }
  return parsed as Record<string, unknown>;
}

/** Read a required non-empty string field, or refuse. Never coerces another type into a string. */
function requireStringField(body: Record<string, unknown>, key: string): string {
  const v = body[key];
  if (typeof v !== 'string' || v.length === 0) {
    throw new PortalAccountError(400, 'missing_field', `missing or invalid "${key}"`);
  }
  return v;
}

/** Resolve the signed-in account from the portal cookie, or refuse 401. */
function requireAccount(deps: PortalApiDeps, req: IncomingMessage): AccountRecord {
  // Try EVERY cookie of that name: on a real domain two can coexist (host-only + Domain=, or
  // apex + www), and refusing both would sign the person out with no error anywhere.
  for (const token of readCookies(req.headers.cookie, PORTAL_COOKIE_NAME)) {
    const accountId = deps.sessions.resolve(token);
    if (accountId === undefined) continue;
    const account = deps.accounts.get(accountId);
    if (account !== undefined) return account;
  }
  throw new UnauthenticatedError();
}

/**
 * The caller's address for rate limiting: the FIRST x-forwarded-for hop when a proxy sits in
 * front (Railway, any load balancer), else the socket. A client can forge the header only when
 * nothing is in front of the process, in which case the socket address is what it forges from.
 */
function clientIp(req: IncomingMessage): string {
  const fwd = req.headers['x-forwarded-for'];
  const first = (Array.isArray(fwd) ? fwd[0] : fwd)?.split(',')[0]?.trim();
  return first !== undefined && first.length > 0 ? first : (req.socket.remoteAddress ?? 'unknown');
}

/**
 * A fixed-window per-key counter. Not a product rate limiter — a stop against the obvious abuse
 * of a public demo: scripted registrations (each later spends testnet funds) and password
 * guessing (each attempt is a synchronous scrypt on the event loop). Memory is bounded by
 * pruning expired windows on every check.
 */
class FixedWindowLimiter {
  readonly #hits = new Map<string, { count: number; resetAt: number }>();

  constructor(
    private readonly limit: number,
    private readonly windowMs: number,
  ) {}

  /** True when the key is over its limit for the current window (and counts the attempt). */
  exceeded(key: string, now = Date.now()): boolean {
    if (this.#hits.size > 10_000) {
      for (const [k, v] of this.#hits) if (v.resetAt <= now) this.#hits.delete(k);
    }
    const cur = this.#hits.get(key);
    if (cur === undefined || cur.resetAt <= now) {
      this.#hits.set(key, { count: 1, resetAt: now + this.windowMs });
      return false;
    }
    cur.count += 1;
    return cur.count > this.limit;
  }
}

const registerLimiter = new FixedWindowLimiter(10, 10 * 60_000); // 10 sign-ups / 10 min / IP
const loginLimiter = new FixedWindowLimiter(20, 10 * 60_000); // 20 attempts / 10 min / IP
const submitLimiter = new FixedWindowLimiter(6, 10 * 60_000); // 6 runs / 10 min / IP
const onrampLimiter = new FixedWindowLimiter(6, 10 * 60_000); // 6 purchases / 10 min / IP

function assertNotRateLimited(limiter: FixedWindowLimiter, req: IncomingMessage, what: string): void {
  if (limiter.exceeded(clientIp(req))) {
    throw new PortalAccountError(429, 'rate_limited', `too many ${what} from this address — try again in a few minutes`);
  }
}

/** Whether to flag the session cookie `Secure`: configured, or the proxy says the hop was https. */
function secureCookies(deps: PortalApiDeps, req: IncomingMessage): boolean {
  if (deps.secureCookies) return true;
  const proto = req.headers['x-forwarded-proto'];
  const first = (Array.isArray(proto) ? proto[0] : proto)?.split(',')[0]?.trim();
  return first === 'https';
}

/**
 * The body of every account-bearing response. The chain flag rides along rather than being
 * inferred, so the page can state plainly that the on-chain half is off BEFORE the user fills in
 * a wizard that cannot complete.
 */
function accountPayload(deps: PortalApiDeps, account: AccountRecord): Record<string, unknown> {
  return {
    account: toPublicAccount(account),
    chainEnabled: deps.chainEnabled,
    activeRunId: deps.runs.activeRunId(account.id) ?? null,
    activeOnrampRunId: deps.onrampRuns.activeRunId(account.id) ?? null,
  };
}

/* -------------------------------------------------------------------------- */
/* SSE — stream one run to its owner                                           */
/* -------------------------------------------------------------------------- */

/**
 * Open an event stream for a run the caller owns. Ownership is checked BEFORE any header is
 * written, so a foreign or unknown run id answers 404 with a JSON body instead of an empty stream.
 */
/** The read side of a run registry, so one stream writer serves KYC and on-ramp runs alike. */
interface StreamableRuns {
  describe(runId: string): { accountId: string; done: boolean } | undefined;
  subscribe(runId: string, accountId: string, listener: (event: RunEvent<unknown>) => void): (() => void) | undefined;
  isDone(runId: string): boolean;
}

function streamRun(
  res: ServerResponse,
  runs: StreamableRuns,
  runId: string,
  account: AccountRecord,
): void {
  const info = runs.describe(runId);
  if (info === undefined || info.accountId !== account.id) {
    throw new PortalAccountError(404, 'not_found', 'no such run');
  }

  res.writeHead(200, {
    'content-type': 'text/event-stream',
    'cache-control': 'no-cache',
    connection: 'keep-alive',
    // Proxies would otherwise buffer the whole stream and deliver it in one lump at the end.
    'x-accel-buffering': 'no',
  });
  res.flushHeaders();

  let closed = false;
  res.on('close', () => {
    closed = true;
  });

  const write = (chunk: string): void => {
    if (closed || res.writableEnded) return;
    try {
      res.write(chunk);
    } catch {
      closed = true;
    }
  };

  // A comment frame every 15 s keeps proxies and idle timeouts from cutting a 40–90 s run.
  const heartbeat = setInterval(() => write(': ping\n\n'), 15_000);
  heartbeat.unref?.();
  res.on('close', () => clearInterval(heartbeat));

  let unsubscribe: (() => void) | undefined;
  const end = (): void => {
    clearInterval(heartbeat);
    if (!closed && !res.writableEnded) res.end();
  };

  const onEvent = (event: RunEvent): void => {
    if (event.type === 'step') {
      write(`data: ${JSON.stringify(event.step)}\n\n`);
      return;
    }
    if (event.type === 'done') {
      write('event: done\ndata: {}\n\n');
    } else {
      write(`event: error\ndata: ${JSON.stringify({ message: event.message })}\n\n`);
    }
    // Terminal. During the buffered replay `unsubscribe` is not yet assigned; the post-subscribe
    // check below covers that case, so both paths close the stream exactly once.
    unsubscribe?.();
    end();
  };

  unsubscribe = runs.subscribe(runId, account.id, onEvent) ?? (() => {});
  if (runs.isDone(runId)) {
    unsubscribe();
    end();
  }
}

/* -------------------------------------------------------------------------- */
/* THE ROUTE TABLE                                                             */
/* -------------------------------------------------------------------------- */

/**
 * Dispatch one `/api/*` request. Always answers; the caller (the demo server) routes by prefix.
 */
export async function handlePortalApi(
  req: IncomingMessage,
  res: ServerResponse,
  url: URL,
  deps: PortalApiDeps,
): Promise<void> {
  const method = (req.method ?? 'GET').toUpperCase();
  const path = url.pathname.replace(/\/+$/, '') || '/';

  try {
    switch (`${method} ${path}`) {
      /* ------------------------------ accounts ----------------------------- */

      case 'POST /api/register': {
        assertNotRateLimited(registerLimiter, req, 'sign-ups');
        const body = await readJsonBody(req);
        const rawEmail = requireStringField(body, 'email');
        const password = requireStringField(body, 'password');
        // Shape first (normalises case), then the business rule the example's copy states.
        const email = assertEmail(rawEmail);
        assertPassword(password);
        const account = deps.accounts.create({ email, password, now: deps.now() });
        // Register the session immediately: a partner portal that makes you sign in again right
        // after signing up is a worse flow, and the cookie is the same one login would set.
        res.setHeader(
          'set-cookie',
          portalSessionCookie(deps.sessions.create(account.id), { secure: secureCookies(deps, req) }),
        );
        sendJson(res, 201, accountPayload(deps, account));
        return;
      }

      case 'POST /api/login': {
        assertNotRateLimited(loginLimiter, req, 'sign-in attempts');
        const body = await readJsonBody(req);
        const email = requireStringField(body, 'email');
        let account: AccountRecord;
        try {
          account = deps.accounts.authenticate(email, requireStringField(body, 'password'));
        } catch (err) {
          // Diagnosable without PII: the account id (or that no such account exists), never the
          // address or the password.
          if (err instanceof InvalidCredentialsError) {
            const known = deps.accounts.findByEmail(email);
            console.warn(
              `[portal-api] login failed for ${known === undefined ? 'an unknown email' : `account ${known.id}`}`,
            );
          }
          throw err;
        }
        res.setHeader(
          'set-cookie',
          portalSessionCookie(deps.sessions.create(account.id), { secure: secureCookies(deps, req) }),
        );
        sendJson(res, 200, accountPayload(deps, account));
        return;
      }

      case 'POST /api/logout': {
        for (const token of readCookies(req.headers.cookie, PORTAL_COOKIE_NAME)) deps.sessions.destroy(token);
        res.setHeader('set-cookie', clearedPortalSessionCookie({ secure: secureCookies(deps, req) }));
        sendJson(res, 200, { ok: true });
        return;
      }

      case 'GET /api/me': {
        const account = requireAccount(deps, req);
        sendJson(res, 200, accountPayload(deps, account));
        return;
      }

      /* -------------------------------- KYC -------------------------------- */

      case 'POST /api/kyc/start': {
        const account = requireAccount(deps, req);
        // The wallet is NOT minted here any more: it is a real contract deployment, so it happens
        // inside the first run (streamed as a step) and is then fixed for the account's lifetime.
        // Re-entering the wizard on an already-verified account leaves the verdict alone; a
        // rejected (or unfinished) account goes back to pending and may try again.
        const updated =
          account.kyc.status === 'approved'
            ? account
            : deps.accounts.update(account.id, { kyc: { ...account.kyc, status: 'pending' } });
        sendJson(res, 200, accountPayload(deps, updated));
        return;
      }

      case 'POST /api/kyc/submit': {
        const account = requireAccount(deps, req);
        const body = await readJsonBody(req);
        const scenario = requireStringField(body, 'scenario');
        if (scenario !== 'approved' && scenario !== 'rejected') {
          throw new PortalAccountError(
            400,
            'invalid_field',
            '"scenario" must be "approved" or "rejected"',
          );
        }
        // Refuse BEFORE starting a run that cannot finish. With no funded signer there is nothing
        // `attest_bbs` can be paid for, and a 40-second run that dies inside the SDK would be a
        // worse answer than this one.
        if (!deps.chainEnabled) {
          throw new PortalAccountError(
            503,
            'chain_unavailable',
            'the on-chain half is disabled on this server (no funded signer at boot), so a ' +
              'credential cannot be attested',
          );
        }
        assertNotRateLimited(submitLimiter, req, 'verification runs');
        const activeRun = deps.runs.activeRunId(account.id);
        if (activeRun !== undefined) {
          // Carries the run id so the page can reattach to the stream instead of showing an error.
          console.warn('[portal-api] 409 run_in_progress');
          sendJson(res, 409, {
            error: { code: 'run_in_progress', message: 'a KYC run is already in progress', runId: activeRun },
          });
          return;
        }
        // Every run deploys a wallet and pays an attestation from the deployer key; a public demo
        // must not let N strangers run N of them at once.
        if (deps.runs.activeCount >= (deps.maxActiveRuns ?? 3)) {
          throw new PortalAccountError(503, 'busy', 'the demo is running its maximum number of verifications right now — try again in a minute');
        }
        // The wizard's answers are what the (mock) provider verifies for THIS run. They travel
        // into the run and nowhere else: not into the account file, not into any step's data.
        const applicant = parseApplicant(body['applicant']);
        const disclose = parseDisclosure(body['disclose']);
        const answer: 'GREEN' | 'RED' = scenario === 'approved' ? 'GREEN' : 'RED';
        deps.accounts.update(account.id, { kyc: { ...account.kyc, status: 'pending' } });
        const accountId = account.id;
        const userName = account.email;

        const runId = deps.runs.start(
          account.id,
          async (emit, ctx) => {
            // ONE wallet per account, deployed on first use and then fixed: it is the subject
            // every credential and every on-chain record is bound to.
            let cAddr = deps.accounts.get(accountId)?.walletCAddr;
            if (cAddr === undefined) {
              const wallet = await deps.createWallet({ userName, emit });
              // Re-read AFTER the deploy: if this run was abandoned by the timeout and a retry
              // already deployed and attested against another wallet, that one is the subject
              // with the record — never overwrite it with a wallet nothing points at.
              const fresh = deps.accounts.get(accountId)?.walletCAddr;
              if (fresh !== undefined) {
                cAddr = fresh;
              } else {
                deps.accounts.update(accountId, {
                  walletCAddr: wallet.address,
                  walletKeyId: wallet.keyId,
                  walletDeployTxHash: wallet.deployTxHash,
                });
                cAddr = wallet.address;
              }
            }
            if (ctx.finished()) {
              throw new Error('run abandoned before the pipeline started (timeout); nothing was written');
            }
            return deps.runPipeline({ cAddr, answer, applicant, disclose, emit });
          },
          (completion) => {
            const current = deps.accounts.get(account.id);
            if (current === undefined) return;
            // An UNEXPECTED fault is not a rejection: leave the account pending so the wizard can
            // be retried once the cause is fixed, rather than marking a person as refused. A LATE
            // result (runner settled after the timeout) is still a real outcome and is persisted,
            // unless a retry has already verified this account in the meantime.
            if (completion.error !== undefined || completion.result === undefined) return;
            if (completion.late === true && current.kyc.status === 'approved') return;
            const result = completion.result;
            const verified = result.txHash !== undefined;
            deps.accounts.update(account.id, {
              kyc: {
                status: verified ? 'approved' : 'rejected',
                ...(verified
                  ? { txHash: result.txHash, verifiedAt: deps.now() }
                  : {}),
                ...(result.claimBitmap === undefined ? {} : { claimBitmap: result.claimBitmap }),
                ...(result.revocationIndex === undefined
                  ? {}
                  : { revocationIndex: result.revocationIndex }),
              },
            });
          },
        );
        sendJson(res, 202, { runId });
        return;
      }

      case 'GET /api/kyc/stream': {
        const account = requireAccount(deps, req);
        const runId = url.searchParams.get('runId');
        if (runId === null || runId.length === 0) {
          throw new PortalAccountError(400, 'missing_field', 'missing "runId"');
        }
        streamRun(res, deps.runs as unknown as StreamableRuns, runId, account);
        return;
      }

      /* ------------------------------ on-ramp ------------------------------ */

      case 'POST /api/onramp/start': {
        const account = requireAccount(deps, req);
        assertNotRateLimited(onrampLimiter, req, 'purchases');
        const body = await readJsonBody(req);
        const raw = body['tryAmount'];
        const tryAmount = typeof raw === 'number' ? raw : Number(raw);
        if (!Number.isFinite(tryAmount) || tryAmount < ONRAMP_MIN_TRY || tryAmount > ONRAMP_MAX_TRY) {
          throw new PortalAccountError(400, 'invalid_field', `"tryAmount" must be between ${ONRAMP_MIN_TRY} and ${ONRAMP_MAX_TRY}`);
        }
        if (!deps.chainEnabled) {
          throw new PortalAccountError(503, 'chain_unavailable', 'the on-chain half is disabled on this server');
        }
        if (account.walletCAddr === undefined || account.kyc.status !== 'approved') {
          throw new PortalAccountError(409, 'not_verified', 'complete identity verification first');
        }
        const active = deps.onrampRuns.activeRunId(account.id);
        if (active !== undefined) {
          sendJson(res, 409, { error: { code: 'run_in_progress', message: 'a purchase is already in progress', runId: active } });
          return;
        }
        const walletCAddr = account.walletCAddr;
        const accountId = account.id;
        const runId = deps.onrampRuns.start(
          accountId,
          (emit) => deps.runOnramp({ accountId, walletCAddr, tryAmount, emit }),
          (completion) => {
            if (completion.result === undefined) return;
            const r = completion.result;
            // The funding account exists either way; a purchase is recorded only once the anchor's
            // payment is on chain — a deposit still pending at the anchor is not a purchase yet.
            deps.accounts.update(accountId, {
              fundingAccount: r.fundingAccount,
              ...(r.stellarTxHash.length === 0
                ? {}
                : { onramp: { tryAmount: r.tryAmount, usdcAmount: r.usdcAmount, stellarTxHash: r.stellarTxHash, at: deps.now() } }),
            });
          },
        );
        sendJson(res, 202, { runId });
        return;
      }

      case 'GET /api/onramp/stream': {
        const account = requireAccount(deps, req);
        const runId = url.searchParams.get('runId');
        if (runId === null || runId.length === 0) {
          throw new PortalAccountError(400, 'missing_field', 'missing "runId"');
        }
        streamRun(res, deps.onrampRuns as unknown as StreamableRuns, runId, account);
        return;
      }

      case 'GET /api/onramp/state': {
        const account = requireAccount(deps, req);
        const allowed = deps.chainEnabled && account.walletCAddr !== undefined && account.kyc.status === 'approved';
        const state = await deps.readOnramp(account.id);
        sendJson(res, 200, { allowed, ...state, last: account.onramp ?? null, min: ONRAMP_MIN_TRY, max: ONRAMP_MAX_TRY });
        return;
      }

      case 'GET /api/kyc/record': {
        const account = requireAccount(deps, req);
        if (!deps.chainEnabled || account.walletCAddr === undefined) {
          // A disabled chain and a wallet-less account are the same answer to this question: there
          // is nothing on chain to read. The flag in the body says which one it was.
          sendJson(res, 200, { view: null, chainEnabled: deps.chainEnabled });
          return;
        }
        sendJson(res, 200, {
          view: await deps.readRecord(account.walletCAddr),
          chainEnabled: true,
          gateContractId: deps.gateContractId,
          chain: deps.chain,
        });
        return;
      }

      default:
        sendJson(res, 404, { error: { code: 'not_found', message: 'no such API route' } });
    }
  } catch (err) {
    sendError(res, err);
  }
}
