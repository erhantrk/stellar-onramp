/**
 * `kyc-gate`'s contract error codes, and how to get one back out of an RPC failure.
 *
 * WHY THIS FILE EXISTS AT ALL. `Error` in `contracts/kyc-gate/src/lib.rs` is `#[repr(u32)]` and
 * deployed clients decode it BY NUMBER — the names never cross the wire. Nothing in the TypeScript
 * world currently knows those names: `stellar contract bindings typescript` emits the ABI but the
 * useful failure text arrives as a free-form host diagnostic string like
 *
 *     HostError: Error(Contract, #15)
 *
 * so every consumer that wants to branch on "was that a losable epoch race or a permanent refusal"
 * ends up pattern-matching a string. Doing that once, here, with the number-to-name map pinned
 * against the Rust source in a test, is strictly better than doing it ad hoc at four call sites.
 */

/**
 * renumbered. They deliberately avoid 300-399, which OpenZeppelin reserves.
 *
 * Codes 8, 9 and 11 are unassigned; deployed clients decode by number, so they are never reused.
 * An unknown code is reported by number rather than by a guessed name.
 *
 * `test/chain/errors.test.ts` parses the `#[contracterror]` enum out of the Rust source and asserts
 * this map matches it exactly, in both directions — a code added on the Rust side without a code
 * added here is a red test, not a mystery in production.
 */
export const KYC_GATE_ERRORS = {
  AlreadyInitialized: 1,
  NotInitialized: 2,
  /** No `ClaimRecord` for this subject. THE ONLY error that means "revocation epoch 0". */
  NoClaimRecord: 3,
  Expired: 4,
  NonceAlreadyUsed: 5,
  InvalidProof: 6,
  UntrustedIssuer: 7,
  StaleAttestation: 10,
  EmptyClaims: 12,
  ExpiryTooFar: 13,
  SubjectRevoked: 14,
  /** The proof was derived for a `revocation_epoch` that is not the subject's current one. */
  RevocationEpochMismatch: 15,
} as const;

export type KycGateErrorName = keyof typeof KYC_GATE_ERRORS;
export type KycGateErrorCode = (typeof KYC_GATE_ERRORS)[KycGateErrorName];

const NAME_BY_CODE: ReadonlyMap<number, KycGateErrorName> = new Map(
  (Object.entries(KYC_GATE_ERRORS) as [KycGateErrorName, number][]).map(([name, code]) => [
    code,
    name,
  ]),
);

/** `15 -> 'RevocationEpochMismatch'`, or `undefined` for a code this build does not know — which
 *  includes retired 8 (`kycGateErrorName(8) === undefined` is CORRECT: old logs carry `#8`, the
 *  live contract no longer emits it, and reporting the number beats inventing a stale name). An
 *  unknown code is NOT an error here: a future contract may add one, and a client that throws on
 *  an unrecognised number is worse than one that reports the number. */
export function kycGateErrorName(code: number): KycGateErrorName | undefined {
  return NAME_BY_CODE.get(code);
}

/**
 * Matched WITH the closing paren, so `#30`..`#39` cannot alias onto `#3`. The exact wire format was
 * `Error(Contract, #15)` against live testnet). `Error(Contract, #N)` is what both the simulation
 * `error` string and the thrown `HostError` carry.
 */
const CONTRACT_ERROR_RE = /Error\(Contract,\s*#(\d+)\)/g;

/**
 * Every string worth searching, drawn out of an unknown thrown value: its own `message`, its
 * `String()` form, and the whole `cause` chain (the SDK wraps). Bounded depth because a `cause`
 * cycle is a hang, and a hang in a signing path is an outage.
 */
function candidateStrings(err: unknown, depth = 0, seen = new Set<unknown>()): string[] {
  if (depth > 8 || err === null || err === undefined) return [];
  if (typeof err === 'object') {
    if (seen.has(err)) return [];
    seen.add(err);
  }
  const out: string[] = [];
  if (typeof err === 'string') out.push(err);
  else if (typeof err === 'object') {
    const rec = err as Record<string, unknown>;
    if (typeof rec['message'] === 'string') out.push(rec['message']);
    // Soroban RPC hands simulation failures back as `{ error: "...", ... }` rather than as a throw.
    if (typeof rec['error'] === 'string') out.push(rec['error']);
    const events = rec['diagnosticEventsXdr'] ?? rec['events'];
    if (Array.isArray(events)) {
      for (const e of events) out.push(...candidateStrings(e, depth + 1, seen));
    }
    if ('cause' in rec) out.push(...candidateStrings(rec['cause'], depth + 1, seen));
    out.push(String(err));
  } else out.push(String(err));
  return out;
}

/**
 * Pull the contract error NUMBER out of whatever the RPC layer threw.
 *
 * FAIL CLOSED ON AMBIGUITY, and this is a deliberate choice rather than laziness. If the haystack
 * mentions two DIFFERENT contract error codes — which happens when a diagnostic bundle is
 * stringified alongside a wrapper error — this returns `undefined` rather than picking one. The
 * only consumer that branches on the result is the re-sign loop, and `undefined` there means "do
 * not retry, surface it". Guessing in the other direction would let a permanent refusal be retried
 * until the attempt cap, burning nonces and hiding the real cause.
 *
 * Returns `undefined` for anything with no `Error(Contract, #N)` in it at all — a transport error,
 * a timeout, a JSON parse failure. Those are not contract errors and must not be treated as any.
 */
export function decodeContractErrorCode(err: unknown): number | undefined {
  const codes = new Set<number>();
  for (const s of candidateStrings(err)) {
    CONTRACT_ERROR_RE.lastIndex = 0;
    for (const m of s.matchAll(CONTRACT_ERROR_RE)) {
      const raw = m[1];
      if (raw === undefined) continue;
      const n = Number.parseInt(raw, 10);
      if (Number.isSafeInteger(n)) codes.add(n);
    }
  }
  if (codes.size !== 1) return undefined;
  const [only] = [...codes];
  return only;
}

/** True iff `err` is exactly this contract error and nothing ambiguous. */
export function isKycGateError(err: unknown, name: KycGateErrorName): boolean {
  return decodeContractErrorCode(err) === KYC_GATE_ERRORS[name];
}

/**
 * The refusals that are RACES and may be retried, versus the refusals that are VERDICTS and may
 * not. There is exactly one member of the first set.
 *
 * `RevocationEpochMismatch` is retriable because the epoch moved under us and re-reading gives the
 * new one. Nothing else is: `SubjectRevoked` (#14), `StaleAttestation` (#10), `LaneDowngrade`
 * (#11), `EmptyClaims` (#12), `ExpiryTooFar` (#13) and `GatewayKeyNotSet` (#9) all describe a
 * condition that an identical retry reproduces exactly, so retrying them is a loop that ends at the
 * attempt cap with the operator none the wiser.
 *
 * `NonceAlreadyUsed` (#5) is NOT retriable either, and it is the interesting one: it means this
 * exact nonce was already spent, which for a correctly generated 32-random-byte nonce means the
 * transaction ALREADY LANDED. Retrying is at best pointless and at worst hides a success.
 */
export const RETRIABLE_ERROR_CODES: ReadonlySet<number> = new Set([
  KYC_GATE_ERRORS.RevocationEpochMismatch,
]);

/** True iff the failure is the epoch race and therefore worth re-reading and re-signing for. */
export function isRetriableContractError(err: unknown): boolean {
  const code = decodeContractErrorCode(err);
  return code !== undefined && RETRIABLE_ERROR_CODES.has(code);
}

/**
 * A decoded contract refusal, carrying the number, the name if this build knows it, and the
 * original throw as `cause` so nothing is lost.
 */
export class KycGateContractError extends Error {
  readonly code: number;
  readonly errorName: KycGateErrorName | undefined;

  constructor(code: number, context: string, cause?: unknown) {
    const name = kycGateErrorName(code);
    super(`kyc-gate refused ${context}: Error(Contract, #${code})${name ? ` = ${name}` : ''}`);
    this.name = 'KycGateContractError';
    this.code = code;
    this.errorName = name;
    if (cause !== undefined) this.cause = cause;
  }
}
