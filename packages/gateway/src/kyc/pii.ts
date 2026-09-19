/**
 * number is ever written to gateway storage, logs, traces, or error payloads."
 *
 * This is the enforcement half of that rule. It is a DETECTOR, not a redactor: it answers "does this
 * artefact contain the secret, in any encoding a leak could plausibly wear" and the answer is used to
 * fail a test or refuse a write. A redactor would be worse than nothing here — it would let the leak
 * happen and then try to un-happen it, and the interesting leaks are the ones nobody predicted.
 *
 * The four encodings, and why each is checked (the shape is lifted from
 *
 *   utf-8         the obvious one: the value made it into a string verbatim.
 *   hex-ascii     the value was hex-encoded on its way into a blob (a Buffer printed with
 *                 `.toString('hex')`, an XDR dump, a `JSON.stringify` of a Buffer's `data` array is
 *                 NOT caught by this and is why the byte-array form below exists).
 *   base64-ascii  the value passed through any base64 layer: a JWT payload, a data URI, an
 *                 `encodedList`, a multipart body.
 *   sha256        a COMMITMENT to the value. This is not a plaintext leak and saying so honestly
 *                 matters, but it IS a correlation handle: anyone holding a list of candidate DOBs
 *                 can hash all 36,500 of them and match. "We hashed it" is not "it is not there".
 *
 * The `sha256` case is the one that catches a well-meaning "we only store a hash of the document
 * number as a dedupe key" design, which is a real design people ship, and which turns a 9-character
 * document number into a rainbow-table lookup.
 */

import { createHash } from 'node:crypto';

/** The encodings a leak is hunted in. Exported so a test can assert the set has not shrunk. */
export const PII_ENCODINGS = Object.freeze([
  'utf-8',
  'hex-ascii',
  'base64-ascii',
  'sha256',
] as const);

export type PiiEncoding = (typeof PII_ENCODINGS)[number];

/**
 * Encodings in which `secret` appears inside `haystack`. Empty means clean.
 *
 * `haystack` is bytes, so this works on a serialised credential, a JSON log line, a stack trace, an
 * XDR blob and a BBS+ proof without the caller having to decide which it is.
 */
export function findEncodings(haystack: Uint8Array, secret: string): PiiEncoding[] {
  const hay = Buffer.from(haystack.buffer, haystack.byteOffset, haystack.byteLength);
  const raw = Buffer.from(secret, 'utf8');
  if (raw.length === 0) return [];
  const candidates: ReadonlyArray<readonly [PiiEncoding, Buffer]> = [
    ['utf-8', raw],
    ['hex-ascii', Buffer.from(raw.toString('hex'), 'utf8')],
    ['base64-ascii', Buffer.from(raw.toString('base64'), 'utf8')],
    ['sha256', createHash('sha256').update(raw).digest()],
  ];
  return candidates.filter(([, needle]) => hay.indexOf(needle) !== -1).map(([name]) => name);
}

/**
 * Flatten anything into the bytes a leak detector should search.
 *
 * An `Error` is handled SPECIALLY and that is the point of this function existing. `JSON.stringify`
 * of an `Error` is `{}` — `message`, `stack` and `cause` are all non-enumerable or absent — so a
 * naive scan of a serialised error is guaranteed to come up clean while the error's `.stack` carries
 * where the rule is most likely to be broken and least likely to be tested.
 *
 * The `cause` chain is walked (the chain track's convention is that every error carries a `cause`),
 * cycle-safely and depth-bounded, because a leak three `cause`s down is still a leak.
 */
/**
 * Separator between the flattened parts, written as an ESCAPE and never as a literal NUL byte in
 * the source.
 *
 * WHY THIS IS NOT A STYLE PREFERENCE. A raw U+0000 anywhere in a .ts file makes git classify the
 * whole module as BINARY: `git diff` prints "Bin 0 -> 8522 bytes" instead of a patch, so every
 * `-a`. The one module whose entire job is proving that PII never reaches a log, an error or a
 * persisted row is the last one that should be unreviewable and ungreppable. Verified with
 * `git diff --no-index --stat /dev/null src/kyc/pii.ts`, which said Bin before this change and
 * reports a line count after it.
 *
 * It is still a NUL because no JSON or UTF-8 artefact under audit can legally contain one, so an
 * attacker-supplied value cannot forge a part boundary and split a secret across two parts.
 */
const NUL_SEPARATOR = '\u0000';

export function auditBytes(value: unknown): Uint8Array {
  const parts: string[] = [];
  const seen = new Set<unknown>();
  collect(value, parts, seen, 0);
  return Buffer.from(parts.join(NUL_SEPARATOR), 'utf8');
}

function collect(value: unknown, out: string[], seen: Set<unknown>, depth: number): void {
  if (depth > 12) return;
  if (value === null || value === undefined) return;
  if (typeof value === 'object') {
    if (seen.has(value)) return;
    seen.add(value);
  }
  if (typeof value === 'string') {
    out.push(value);
    return;
  }
  if (typeof value === 'number' || typeof value === 'boolean' || typeof value === 'bigint') {
    out.push(String(value));
    return;
  }
  if (value instanceof Uint8Array) {
    // BOTH forms. The raw bytes catch a value spliced into a binary blob; the hex catches nothing
    // extra by itself, but `findEncodings` searches for the hex-ASCII of the secret, and that only
    // matches if the haystack CONTAINS hex text — which it does once we append this.
    out.push(Buffer.from(value.buffer, value.byteOffset, value.byteLength).toString('binary'));
    out.push(Buffer.from(value.buffer, value.byteOffset, value.byteLength).toString('hex'));
    return;
  }
  if (value instanceof Error) {
    out.push(value.name, value.message, value.stack ?? '');
    collect((value as { cause?: unknown }).cause, out, seen, depth + 1);
    // Own enumerable properties of an Error subclass (our errors carry `reason`, `subject`, ...).
    for (const key of Object.keys(value)) {
      out.push(key);
      collect((value as unknown as Record<string, unknown>)[key], out, seen, depth + 1);
    }
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) collect(item, out, seen, depth + 1);
    return;
  }
  if (value instanceof Map) {
    for (const [k, v] of value) {
      collect(k, out, seen, depth + 1);
      collect(v, out, seen, depth + 1);
    }
    return;
  }
  if (value instanceof Set) {
    for (const item of value) collect(item, out, seen, depth + 1);
    return;
  }
  if (typeof value === 'object') {
    for (const key of Object.keys(value)) {
      // The KEY is collected too: `{"1990-05-04": true}` is a leak in a key, not a value, and a
      // values-only scan misses it entirely.
      out.push(key);
      collect((value as Record<string, unknown>)[key], out, seen, depth + 1);
    }
    return;
  }
  out.push(String(value));
}

export class PiiLeakError extends Error {
  override readonly name = 'PiiLeakError';
  readonly encodings: readonly PiiEncoding[];
  readonly label: string;
  constructor(label: string, artefact: string, encodings: readonly PiiEncoding[]) {
    super(
      `refusing to emit ${artefact}: it contains the ${label} in ${encodings.join(', ')} form. ` +
        'the no-PII rule forbids a name, DOB or document number in gateway storage, logs, ' +
        'traces or error payloads. Note that the value itself is NOT quoted in this message — ' +
        'doing so would make the leak detector a leak.',
    );
    this.encodings = encodings;
    this.label = label;
  }
}

/** One PII value, with a label safe to put in an error message. The value never is. */
export interface PiiSecret {
  /** e.g. "date of birth". Safe to log. */
  readonly label: string;
  /** The value. NEVER logged, never put in an error message. */
  readonly value: string;
}

/**
 * Throw if any secret appears in `artefact`, in any encoding.
 *
 * Use this at every boundary where something leaves the process: the returned ClaimSet, the
 * serialised credential, each log record, each error (including `.stack`), and the persisted tuple.
 * It is cheap — four `Buffer.indexOf` per secret — and it is the difference between "the schema has
 * no PII attribute so the credential cannot leak" being an argument and being a test.
 */
export function assertNoPii(
  artefact: unknown,
  secrets: readonly PiiSecret[],
  what: string,
): void {
  const hay = auditBytes(artefact);
  for (const secret of secrets) {
    const found = findEncodings(hay, secret.value);
    if (found.length > 0) throw new PiiLeakError(secret.label, what, found);
  }
}

/**
 * The control every leak test needs and most leak tests omit: prove the detector would have FOUND a
 * leak in this artefact if there were one. A detector that silently searches the wrong bytes
 * (because `auditBytes` returned `{}` for an Error, say) reports "clean" for everything, and a suite
 * of green leak tests is then evidence of nothing at all.
 *
 * Returns the encodings in which `canary` was found; a caller asserts it is non-empty.
 */
export function detectorControl(artefact: unknown, canary: string): PiiEncoding[] {
  return findEncodings(auditBytes(artefact), canary);
}
