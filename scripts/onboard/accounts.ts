/**
 * The onboarding portal's ACCOUNT LAYER: sign-up, sign-in, and the durable per-account KYC state
 * that the portal's dashboard reads back.
 *
 * WHY THIS LIVES IN `scripts/`, NOT `apps/gateway-http`. The gateway is the KYC/credential
 * authority; it deliberately has NO user model — its only "session" is a transient, wallet-keyed
 * onboarding session (`apps/gateway-http/src/seams/session-store.ts`). An end-user account with an
 * email and a password is a HOST-APPLICATION concern, exactly like obtaining a session JWT is
 * (see `packages/sdk/src/gateway-client.ts`: "OBTAINING the token is deliberately not this
 * client's job"). So the account lives here, beside the demo server that hosts the portal, and the
 * gateway stays untouched.
 *
 * TWO STORES, DELIBERATELY SEPARATE:
 *
 *   * {@link JsonFileAccountStore} — the DURABLE record: email, password hash, wallet C-address,
 *     and the KYC verdict. Written atomically to a JSON file so accounts survive a server restart.
 *   * {@link PortalSessionStore} — the SIGN-IN session: an opaque token in an HttpOnly cookie
 *     mapping to an account id, with a 24 h TTL. Given a file it persists sha256(token) — never
 *
 * THE PII RULE, AND WHY THE RECORD LOOKS SPARSE. The KYC wizard collects a name, a date of birth
 * and a document number — and NONE of that is ever written here. The account file holds the six
 * derived booleans' OUTCOME (a status string plus the claim bitmap), the wallet address, and the
 * transaction hash. That mirrors the system's own claim: the durable artefact is a claim about a
 * person, never the person's documents. Do not "round out" this record with the form fields.
 */

import { createHash, randomBytes, randomUUID, scryptSync, timingSafeEqual } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';

/* -------------------------------------------------------------------------- */
/* Errors — every one carries the HTTP shape the API layer should answer with   */
/* -------------------------------------------------------------------------- */

/** Base class for every refusal this module can raise, each with its HTTP status + machine code. */
export class PortalAccountError extends Error {
  readonly status: number;
  readonly code: string;
  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = 'PortalAccountError';
    this.status = status;
    this.code = code;
  }
}

export class InvalidEmailError extends PortalAccountError {
  constructor(message = 'enter a valid email address') {
    super(400, 'invalid_email', message);
  }
}


export class WeakPasswordError extends PortalAccountError {
  constructor(message: string) {
    super(400, 'weak_password', message);
  }
}

export class EmailInUseError extends PortalAccountError {
  constructor() {
    super(409, 'email_in_use', 'an account already exists for this email');
  }
}

export class InvalidCredentialsError extends PortalAccountError {
  constructor() {
    // One message for "no such email" and "wrong password" alike: which of the two it was is not
    // something an unauthenticated caller should be able to probe.
    super(401, 'invalid_credentials', 'email or password is incorrect');
  }
}

export class UnauthenticatedError extends PortalAccountError {
  constructor() {
    super(401, 'unauthenticated', 'sign in to continue');
  }
}

/* -------------------------------------------------------------------------- */
/* Email + password rules                                                      */
/* -------------------------------------------------------------------------- */


/** The password floor. Length only: no composition rules, which push people toward worse secrets. */
export const MIN_PASSWORD_LENGTH = 8;

/**
 * Normalize an email for storage and lookup: trim, lowercase. A single canonical form is what makes
 * "the same address with different case" collide correctly at `email_in_use` time.
 */
export function normalizeEmail(raw: string): string {
  return raw.trim().toLowerCase();
}

/**
 * Reject anything that is not a plausible address. A deliberately loose shape check — one `@`, a
 * non-empty local part, a dotted domain, no whitespace — because the authoritative validation of
 * an address is whether mail reaches it, which this demo never attempts.
 */
export function assertEmail(raw: string): string {
  const email = normalizeEmail(raw);
  if (email.length === 0 || email.length > 254) throw new InvalidEmailError();
  if (/\s/.test(email)) throw new InvalidEmailError();
  const at = email.indexOf('@');
  if (at <= 0 || at !== email.lastIndexOf('@')) throw new InvalidEmailError();
  const domain = email.slice(at + 1);
  if (!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(domain)) throw new InvalidEmailError();
  return email;
}


/* -------------------------------------------------------------------------- */
/* Password hashing — scrypt, salted, constant-time verify                     */
/* -------------------------------------------------------------------------- */

/** scrypt parameters. `N` is the work factor; memory is ~128·N·r = 16 MiB, inside node's 32 MiB cap. */
const SCRYPT_N = 16_384;
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const SCRYPT_KEY_BYTES = 32;
const SALT_BYTES = 16;

/**
 * Hash a password as `scrypt$N$r$p$saltHex$hashHex`. All parameters travel WITH the hash so a
 * future cost bump can coexist with existing records instead of invalidating them.
 */
export function hashPassword(password: string): string {
  const salt = randomBytes(SALT_BYTES);
  const hash = scryptSync(password, salt, SCRYPT_KEY_BYTES, {
    N: SCRYPT_N,
    r: SCRYPT_R,
    p: SCRYPT_P,
  });
  return [
    'scrypt',
    String(SCRYPT_N),
    String(SCRYPT_R),
    String(SCRYPT_P),
    salt.toString('hex'),
    hash.toString('hex'),
  ].join('$');
}

/**
 * Verify a password against a stored hash in constant time. Returns `false` for a malformed stored
 * string rather than throwing: a corrupt record must fail closed, not crash the sign-in route.
 */
export function verifyPassword(password: string, stored: string): boolean {
  const parts = stored.split('$');
  if (parts.length !== 6 || parts[0] !== 'scrypt') return false;
  const N = Number(parts[1]);
  const r = Number(parts[2]);
  const p = Number(parts[3]);
  const salt = parts[4];
  const expectedHex = parts[5];
  if (
    salt === undefined ||
    expectedHex === undefined ||
    !Number.isInteger(N) ||
    !Number.isInteger(r) ||
    !Number.isInteger(p)
  ) {
    return false;
  }
  const expected = Buffer.from(expectedHex, 'hex');
  if (expected.length === 0) return false;
  let actual: Buffer;
  try {
    actual = scryptSync(password, Buffer.from(salt, 'hex'), expected.length, { N, r, p });
  } catch {
    // Out-of-range parameters in a tampered record: refuse rather than attempt the work.
    return false;
  }
  return expected.length === actual.length && timingSafeEqual(expected, actual);
}

/** Assert the password policy, throwing {@link WeakPasswordError} with a readable reason. */
export function assertPassword(password: string): void {
  if (typeof password !== 'string' || password.length < MIN_PASSWORD_LENGTH) {
    throw new WeakPasswordError(`password must be at least ${MIN_PASSWORD_LENGTH} characters`);
  }
  if (password.length > 1024) {
    throw new WeakPasswordError('password is too long');
  }
}

/* -------------------------------------------------------------------------- */
/* The durable record                                                          */
/* -------------------------------------------------------------------------- */

/**
 * The KYC verdict as the portal shows it.
 *
 *   none     — the wizard has not been started.
 *   pending  — the wizard is in flight (or was abandoned mid-run); the wallet is deployed by the
 *              first run itself, so a pending account may or may not have one yet.
 *   rejected — the provider refused, so nothing was ever issued or written.
 */
export type KycStatus = 'none' | 'pending' | 'approved' | 'rejected';

/**
 * Everything durable about an account's KYC state. Deliberately holds NO PII: no name, no date of
 * birth, no document number — only the outcome and its on-chain handles.
 */
export interface AccountKyc {
  status: KycStatus;
  /** The gateway onboarding session the run used (an opaque id, safe to keep for support). */
  sessionId?: string;
  /** The granted claim bitmap that landed on chain (`attest_bbs`'s `claims` argument). */
  claimBitmap?: number;
  /** The credential's audit-link index, signed into the record. */
  revocationIndex?: number;
  /** The `attest_bbs` transaction hash, when the record landed. */
  txHash?: string;
  /** Unix seconds when the record landed. */
  verifiedAt?: number;
}

export interface AccountRecord {
  readonly id: string;
  readonly email: string;
  /** `scrypt$…` — never the plaintext, never logged. */
  readonly passwordHash: string;
  readonly createdAt: number;
  /**
   * The account's passkey wallet contract address (`C…`), deployed on testnet during the first
   * KYC run (scripts/onboard/wallet.ts) and then fixed for the account's lifetime. Absent until
   * then — the portal has no wallet to bind a credential to before that.
   */
  readonly walletCAddr?: string;
  /** The passkey credential id (base64url) the wallet contract was deployed with. */
  readonly walletKeyId?: string;
  /** The transaction that deployed the wallet contract on testnet. */
  readonly walletDeployTxHash?: string;
  readonly kyc: AccountKyc;
}

/** What the portal is allowed to send back to the browser. Same shape, minus the password hash. */
export interface PublicAccount {
  id: string;
  email: string;
  createdAt: number;
  walletCAddr: string | null;
  walletDeployTxHash: string | null;
  kyc: AccountKyc;
}

export function toPublicAccount(account: AccountRecord): PublicAccount {
  return {
    id: account.id,
    email: account.email,
    createdAt: account.createdAt,
    walletCAddr: account.walletCAddr ?? null,
    walletDeployTxHash: account.walletDeployTxHash ?? null,
    kyc: { ...account.kyc },
  };
}

/* -------------------------------------------------------------------------- */
/* The store                                                                   */
/* -------------------------------------------------------------------------- */

interface PersistedFile {
  version: 1;
  accounts: AccountRecord[];
}

/**
 * A JSON-file account store: load once at boot, write atomically on every mutation.
 *
 * The write is `write temp + rename` rather than a truncating write, because the alternative loses
 * every account on a crash mid-write. One process is assumed (this is a local demo server); there
 * is no cross-process locking, and the docblock says so rather than pretending otherwise.
 */
export class JsonFileAccountStore {
  readonly #file: string;
  readonly #accounts = new Map<string, AccountRecord>();
  readonly #byEmail = new Map<string, string>();

  constructor(file: string) {
    this.#file = file;
    this.#load();
  }

  #load(): void {
    if (!existsSync(this.#file)) return;
    let parsed: PersistedFile;
    try {
      parsed = JSON.parse(readFileSync(this.#file, 'utf8')) as PersistedFile;
    } catch (cause) {
      // Loud, and fatal: silently starting empty would look like "all accounts vanished" and the
      // next write would overwrite the file this process could not read.
      throw new Error(
        `[portal] the account file at ${this.#file} is not readable JSON (${String(
          (cause as Error)?.message ?? cause,
        )}). Fix or delete it before starting the portal.`,
      );
    }
    for (const account of parsed.accounts ?? []) {
      this.#accounts.set(account.id, account);
      this.#byEmail.set(account.email, account.id);
    }
  }

  #persist(): void {
    const payload: PersistedFile = { version: 1, accounts: [...this.#accounts.values()] };
    mkdirSync(dirname(this.#file), { recursive: true });
    const temp = `${this.#file}.${process.pid}.tmp`;
    writeFileSync(temp, `${JSON.stringify(payload, null, 2)}\n`, 'utf8');
    renameSync(temp, this.#file);
  }

  get size(): number {
    return this.#accounts.size;
  }

  get(id: string): AccountRecord | undefined {
    return this.#accounts.get(id);
  }

  findByEmail(email: string): AccountRecord | undefined {
    const id = this.#byEmail.get(normalizeEmail(email));
    return id === undefined ? undefined : this.#accounts.get(id);
  }

  /** Create an account. Throws {@link EmailInUseError} if the address is taken. */
  create(args: { email: string; password: string; now?: number }): AccountRecord {
    const email = assertEmail(args.email);
    assertPassword(args.password);
    if (this.#byEmail.has(email)) throw new EmailInUseError();
    const account: AccountRecord = {
      id: randomUUID(),
      email,
      passwordHash: hashPassword(args.password),
      createdAt: args.now ?? Math.floor(Date.now() / 1000),
      kyc: { status: 'none' },
    };
    this.#accounts.set(account.id, account);
    this.#byEmail.set(email, account.id);
    this.#persist();
    return account;
  }

  /**
   * Check a password. Throws {@link InvalidCredentialsError} for BOTH an unknown email and a wrong
   * password — the caller must not be able to tell the two apart.
   */
  authenticate(email: string, password: string): AccountRecord {
    const account = this.findByEmail(email);
    if (account === undefined || !verifyPassword(password, account.passwordHash)) {
      throw new InvalidCredentialsError();
    }
    return account;
  }

  /** Patch an account and persist. Returns the updated record. */
  update(
    id: string,
    patch: Partial<Pick<AccountRecord, 'walletCAddr' | 'walletKeyId' | 'walletDeployTxHash' | 'kyc'>>,
  ): AccountRecord {
    const existing = this.#accounts.get(id);
    if (existing === undefined) throw new UnauthenticatedError();
    const next: AccountRecord = {
      ...existing,
      ...(patch.walletCAddr === undefined ? {} : { walletCAddr: patch.walletCAddr }),
      ...(patch.walletKeyId === undefined ? {} : { walletKeyId: patch.walletKeyId }),
      ...(patch.walletDeployTxHash === undefined
        ? {}
        : { walletDeployTxHash: patch.walletDeployTxHash }),
      ...(patch.kyc === undefined ? {} : { kyc: patch.kyc }),
    };
    this.#accounts.set(id, next);
    this.#persist();
    return next;
  }
}

/* -------------------------------------------------------------------------- */
/* Sign-in sessions                                                            */
/* -------------------------------------------------------------------------- */

/** The cookie the portal session token rides in. */
export const PORTAL_COOKIE_NAME = 'portal_session';

/**
 * Sign-in sessions: an opaque token -> account id, with a TTL.
 *
 * In-memory by default (tests, and the same behaviour as before: a restart signs everyone out).
 * partner must not be signed out by every deploy. What hits disk is `sha256(token)`, never the
 * token: the cookie is the only bearer, and a copy of the file cannot impersonate anyone.
 * Expired entries are dropped lazily on resolve and on load.
 */
export interface PortalSessionStoreOptions {
  readonly file?: string;
  /** Default 24 h — matches the cookie's Max-Age. */
  readonly ttlSeconds?: number;
  readonly now?: () => number;
}

interface PersistedSession {
  tokenHash: string;
  accountId: string;
  expiresAt: number;
}

interface PersistedSessionsFile {
  version: 1;
  sessions: PersistedSession[];
}

export const SESSION_TTL_SECONDS = 86_400;

export class PortalSessionStore {
  readonly #byHash = new Map<string, PersistedSession>();
  readonly #file: string | undefined;
  readonly #ttl: number;
  readonly #now: () => number;

  constructor(options: PortalSessionStoreOptions = {}) {
    this.#file = options.file;
    this.#ttl = options.ttlSeconds ?? SESSION_TTL_SECONDS;
    this.#now = options.now ?? (() => Math.floor(Date.now() / 1000));
    this.#load();
  }

  #load(): void {
    if (this.#file === undefined || !existsSync(this.#file)) return;
    let parsed: unknown;
    try {
      parsed = JSON.parse(readFileSync(this.#file, 'utf8'));
    } catch (cause) {
      throw new Error(`${this.#file} is not readable JSON; refusing to guess at sessions`, { cause });
    }
    const file = parsed as Partial<PersistedSessionsFile>;
    if (file.version !== 1 || !Array.isArray(file.sessions)) {
      throw new Error(`${this.#file} is not a version-1 sessions file`);
    }
    const now = this.#now();
    for (const rec of file.sessions) {
      if (typeof rec.tokenHash === 'string' && typeof rec.accountId === 'string' && rec.expiresAt > now) {
        this.#byHash.set(rec.tokenHash, rec);
      }
    }
  }

  #persist(): void {
    if (this.#file === undefined) return;
    mkdirSync(dirname(this.#file), { recursive: true });
    const body: PersistedSessionsFile = { version: 1, sessions: [...this.#byHash.values()] };
    const tmp = `${this.#file}.${process.pid}.tmp`;
    writeFileSync(tmp, JSON.stringify(body), { mode: 0o600 });
    renameSync(tmp, this.#file);
  }

  #sweep(): void {
    const now = this.#now();
    let dropped = false;
    for (const [hash, rec] of this.#byHash) {
      if (rec.expiresAt <= now) {
        this.#byHash.delete(hash);
        dropped = true;
      }
    }
    if (dropped) this.#persist();
  }

  create(accountId: string): string {
    this.#sweep();
    const token = randomBytes(32).toString('base64url');
    this.#byHash.set(hashToken(token), {
      tokenHash: hashToken(token),
      accountId,
      expiresAt: this.#now() + this.#ttl,
    });
    this.#persist();
    return token;
  }

  /** The account id behind a token, or `undefined` when the token is unknown or expired. */
  resolve(token: string | undefined): string | undefined {
    if (token === undefined || token.length === 0) return undefined;
    const rec = this.#byHash.get(hashToken(token));
    if (rec === undefined) return undefined;
    if (rec.expiresAt <= this.#now()) {
      this.#byHash.delete(rec.tokenHash);
      this.#persist();
      return undefined;
    }
    return rec.accountId;
  }

  destroy(token: string | undefined): void {
    if (token === undefined) return;
    if (this.#byHash.delete(hashToken(token))) this.#persist();
  }

  get size(): number {
    return this.#byHash.size;
  }
}

function hashToken(token: string): string {
  return createHash('sha256').update(token, 'utf8').digest('hex');
}

/** `Set-Cookie` for a portal session. HttpOnly + SameSite=Lax; `Secure` only when the deployment says it serves https. */
export function portalSessionCookie(token: string, options: { secure?: boolean } = {}): string {
  return (
    `${PORTAL_COOKIE_NAME}=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${SESSION_TTL_SECONDS}` +
    (options.secure ? '; Secure' : '')
  );
}

/** The `Set-Cookie` value that clears the portal session. */
export function clearedPortalSessionCookie(options: { secure?: boolean } = {}): string {
  return `${PORTAL_COOKIE_NAME}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0` + (options.secure ? '; Secure' : '');
}

/**
 * Every value carried under `name` in a raw `Cookie` header, in order. A real domain can end up
 * with two cookies of the same name (a host-only one and a `Domain=` one, or apex and www); the
 * caller tries each against the session store rather than signing the person out silently.
 */
export function readCookies(header: string | undefined, name: string): string[] {
  if (header === undefined) return [];
  const values: string[] = [];
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq === -1) continue;
    if (part.slice(0, eq).trim() !== name) continue;
    const value = part.slice(eq + 1).trim();
    if (value.length > 0) values.push(value);
  }
  return values;
}
