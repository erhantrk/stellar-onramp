/**
 * W3C Bitstring Status List v1.0 — decode half only.
 *
 * Spec: https://www.w3.org/TR/vc-bitstring-status-list/  (W3C Recommendation)
 * This file implements §3.4 Bitstring Expansion, the bit read of §3.2 step 10, and the two
 * guards of §3.2 steps 5 and 9. It deliberately does NOT implement §3.2 step 4 ("Dereference
 * the statusListCredential URL"): that is a network fetch, and @stellaronramp/identity makes no
 * network calls (see the package header in index.ts). The CALLER dereferences the URL, verifies
 * the status list credential's own proof, and hands us the resulting object — or hands us a
 * resolver callback that does so. Network ownership stays with the caller, always.
 *
 * WHY THIS EXISTS AT ALL: schema index 2 is `revocationIndex`, `gateOnrampPredicate()` discloses
 * revoked off-chain and every verifier would still say `valid: true`.
 *
 * ENCODING, IN THE SPEC'S OWN WORDS (§2.2, normative):
 *   "The `encodedList` property of the credential subject MUST be a Multibase-encoded base64url
 *    (with no padding) [RFC4648] representation of the GZIP-compressed [RFC1952] bitstring values
 *    for the associated range of verifiable credential status values. The uncompressed bitstring
 *    MUST be at least 16KB in size. The bitstring MUST be encoded such that the first index, with
 *    a value of zero (0), is located at the left-most bit in the bitstring and the last index,
 *    with a value of one less than the length of the bitstring (bitstring_length - 1), is located
 *    at the right-most bit in the bitstring."
 *
 * Read that sentence three times before changing anything here. It fixes, in order:
 *   1. the pipeline direction — GZIP first, THEN base64url, THEN the multibase prefix, so
 *      decoding runs multibase -> base64url -> gunzip;
 *   2. the 16 KB floor, which is on the UNCOMPRESSED bitstring, not the encoded string;
 *   3. the bit order — index 0 is the LEFT-MOST bit, i.e. mask 0x80 of byte 0, NOT 0x01.
 * §7.1 spells out why item 3 matters: "Failure to do so can result in checking the wrong bitstring
 * index for a given credential, leading to a misinterpretation of its present state (e.g.,
 * mistaking a revoked status for an unrevoked status)."
 */

export class StatusListError extends Error {
  override readonly name = 'StatusListError';
}

/**
 * §3.2 Validate Algorithm step 2: "Let minimumNumberOfEntries be 131,072 unless a different lower
 * bound is established by a specific ecosystem specification."
 *
 * This is a PRIVACY floor, not a formatting nit, and a list below it is REJECTED rather than
 * padded. §5 of the spec: the size "ensures an adequate amount of group privacy in the average
 * case". With a hundred-entry list, "the credential at index 42 of this list" is close to a name.
 * Padding a short list would manufacture the anonymity set the issuer failed to provide.
 */
export const MINIMUM_STATUS_LIST_ENTRIES = 131_072;

/** The same floor expressed on the bitstring: 131,072 bits = 16 KB (§3.3 step 1, §2.2). */
export const MINIMUM_STATUS_LIST_BYTES = MINIMUM_STATUS_LIST_ENTRIES / 8;

/**
 * Decompression bomb ceiling: 16 MiB uncompressed, i.e. 134,217,728 single-bit entries.
 * The caller fetched `encodedList` off the network, so it is attacker-influenced input; GZIP
 * expands ~1000x on zero-filled data and a few hundred KB of it would exhaust memory. We stop
 * reading as soon as this is exceeded rather than buffering first and checking after.
 */
export const MAX_STATUS_LIST_BYTES = 16 * 1024 * 1024;

/**
 * Multibase header for base64url-no-pad, from the table in https://www.w3.org/TR/cid-1.0/ §2.4:
 * "u | The base-64-url-no-pad alphabet is used to encode the bytes."
 * Confirmed against every `encodedList` example in the status-list spec, all of which begin "u".
 */
export const MULTIBASE_BASE64URL_NOPAD_PREFIX = 'u';

/**
 * The purposes this package will ACT on. §2.1 also defines `refresh` and `message`; both are
 * rejected here, because neither answers "may I accept this credential" and silently treating an
 * unrecognised purpose as "not revoked" is the precise failure this module exists to prevent.
 */
export const STATUS_PURPOSES = ['revocation', 'suspension'] as const;
export type StatusPurpose = (typeof STATUS_PURPOSES)[number];

/**
 * One entry of `statusMessage`. §2.2, verbatim: each element "MUST contain the two properties
 * described below" — "`status`, a string representing the hexadecimal value of the status
 * prefixed with `0x`" and "`message`, a string used by software developers to assist with
 * debugging".
 */
export interface StatusMessage {
  /** Hex value of the status, `0x`-prefixed. */
  readonly status: string;
  /** Human-readable label. Debugging aid only; carries no authority. */
  readonly message: string;
}

/**
 * The already-resolved status list, in W3C wire shape. This is `credentialSubject` of a
 * `BitstringStatusListCredential` — the caller strips the VC envelope and verifies its proof.
 */
export interface BitstringStatusList {
  /** §2.1. Must be one of STATUS_PURPOSES; anything else is rejected. */
  readonly statusPurpose: string;
  /** §2.2. Multibase("u") ‖ base64url-no-pad( gzip( bitstring ) ). */
  readonly encodedList: string;
  /**
   * §2.2: "statusSize MAY be provided. If statusSize is not present ... then statusSize MUST be
   * processed as 1. If present, statusSize MUST be an integer greater than zero."
   */
  readonly statusSize?: number;
  /**
   * §2.2: "`statusMessage` MAY be present if `statusSize` is `1`, and MUST be present if
   * `statusSize` is greater than `1`", with "the length of which MUST equal the number of possible
   * status messages indicated by `statusSize`" — 2 elements at 1 bit, 4 at 2 bits, 8 at 3 bits.
   *
   */
  readonly statusMessage?: readonly StatusMessage[];
}

/** What a resolver callback is told. It is everything the proof disclosed that identifies a list. */
export interface StatusListRequest {
  /** Claim index 2, `revocationIndex` — the spec's `statusListIndex`. */
  readonly revocationIndex: number;
  /** Claim index 1, if the proof disclosed it. `undefined` when index 1 stays hidden. */
  readonly issuerId: string | undefined;
  /** The purpose the verifier is asking about. */
  readonly statusPurpose: StatusPurpose;
}

/**
 * Caller-supplied lookup. THIS is where the network lives, in the caller's code, not ours.
 * Throwing from here fails verification closed (reason `status-list-invalid`).
 */
export type StatusListResolver = (
  request: StatusListRequest,
) => BitstringStatusList | Promise<BitstringStatusList>;

export interface DecodedStatusList {
  readonly statusPurpose: StatusPurpose;
  readonly statusSize: number;
  /** The uncompressed bitstring, index 0 == most significant bit of `bits[0]`. */
  readonly bits: Uint8Array;
  /** `bits.length * 8`. */
  readonly bitLength: number;
  /** `floor(bitLength / statusSize)` — the spec's "length of the bitstring divided by statusSize". */
  readonly entryCount: number;
}

export interface DecodeStatusListOptions {
  /**
   * §3.2 step 5: "Verify that the status purpose is equal to a statusPurpose value in the
   * statusListCredential." Supplying a list whose purpose differs from the one being asked about
   * is an error, not a pass.
   */
  readonly expectedPurpose?: StatusPurpose;
}

/* -------------------------------------------------------------------------- */
/* base64url (RFC 4648 §5), no padding — hand-rolled to stay browser-safe      */
/* -------------------------------------------------------------------------- */

const B64URL_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

const B64URL_REVERSE: Int8Array = (() => {
  const t = new Int8Array(128).fill(-1);
  for (let i = 0; i < B64URL_ALPHABET.length; i++) {
    t[B64URL_ALPHABET.charCodeAt(i)] = i;
  }
  return t;
})();

/**
 * Strict base64url decode, no padding accepted, no whitespace tolerated, no standard-base64
 * `+`/`/` accepted. Strict because a lenient decoder turns a corrupt list into a plausible one.
 */
export function base64urlDecode(s: string): Uint8Array {
  const n = s.length;
  if (n % 4 === 1) throw new StatusListError('base64url string has an impossible length');
  const full = n >> 2;
  const rem = n & 3;
  const out = new Uint8Array(full * 3 + (rem === 0 ? 0 : rem - 1));
  let o = 0;
  let acc = 0;
  let bits = 0;
  for (let i = 0; i < n; i++) {
    const code = s.charCodeAt(i);
    const v = code < 128 ? B64URL_REVERSE[code] : undefined;
    if (v === undefined || v < 0) {
      throw new StatusListError(
        `"${s[i] ?? ''}" is not a base64url character (padding "=" is not allowed either)`,
      );
    }
    acc = (acc << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (acc >> bits) & 0xff;
    }
  }
  // The leftover bits of the final partial group MUST be zero, otherwise two distinct strings
  // decode to the same bytes and the encoding stops being canonical.
  if (bits > 0 && (acc & ((1 << bits) - 1)) !== 0) {
    throw new StatusListError('base64url string has non-canonical trailing bits');
  }
  if (o !== out.length) throw new StatusListError('internal: base64url length miscount');
  return out;
}

/** `B64URL_ALPHABET[i]` as a definitely-defined character (`noUncheckedIndexedAccess`). */
function b64char(sextet: number): string {
  return B64URL_ALPHABET.charAt(sextet);
}

/** Inverse of `base64urlDecode`. Used by `encodeStatusList`. */
export function base64urlEncode(bytes: Uint8Array): string {
  let out = '';
  let i = 0;
  for (; i + 3 <= bytes.length; i += 3) {
    const a = bytes[i] as number;
    const b = bytes[i + 1] as number;
    const c = bytes[i + 2] as number;
    const n = (a << 16) | (b << 8) | c;
    out += b64char((n >> 18) & 63) + b64char((n >> 12) & 63) + b64char((n >> 6) & 63) + b64char(n & 63);
  }
  const left = bytes.length - i;
  if (left === 1) {
    const a = bytes[i] as number;
    out += b64char(a >> 2) + b64char((a << 4) & 63);
  } else if (left === 2) {
    const a = bytes[i] as number;
    const b = bytes[i + 1] as number;
    out += b64char(a >> 2) + b64char(((a << 4) | (b >> 4)) & 63) + b64char((b << 2) & 63);
  }
  return out;
}

/** Multibase decode: strip and validate the one-character header (cid-1.0 §3.2 Base Decode). */
export function multibaseDecode(s: string): Uint8Array {
  if (typeof s !== 'string' || s.length === 0) {
    throw new StatusListError('encodedList must be a non-empty multibase string');
  }
  const prefix = s[0];
  if (prefix !== MULTIBASE_BASE64URL_NOPAD_PREFIX) {
    throw new StatusListError(
      `encodedList must use the multibase "${MULTIBASE_BASE64URL_NOPAD_PREFIX}" ` +
        `(base64url-no-pad) prefix, got "${String(prefix)}"`,
    );
  }
  return base64urlDecode(s.slice(1));
}

/* -------------------------------------------------------------------------- */
/* GZIP                                                                        */
/* -------------------------------------------------------------------------- */

/**
 * GZIP decompression via the WHATWG Compression Streams API.
 *
 * WHY DecompressionStream AND NOT node:zlib: this package's contract is "pure TypeScript, no
 * chain access, no network calls" and it is meant to be usable by a browser wallet SDK as well as
 * by the Node gateway. `node:zlib.gunzipSync` would make every import of @stellaronramp/identity
 * fail to bundle for the browser. `DecompressionStream("gzip")` is a web standard, present in
 * Node >= 18 (this repo pins >= 22) and in every current browser, and needs NO new dependency —
 * Cost of the alternative: either a browser-hostile Node built-in, or a third-party inflate
 * (pako, fflate) that would be a new runtime dependency for something the platform already ships.
 * The price paid is that decoding is async; `verifyDetailed` is already async, so nothing changes
 * at the call site.
 */
async function gunzip(compressed: Uint8Array): Promise<Uint8Array> {
  if (typeof DecompressionStream !== 'function') {
    throw new StatusListError(
      'DecompressionStream("gzip") is unavailable in this runtime; Node >= 18 or a modern browser ' +
        'is required to decode a Bitstring Status List',
    );
  }
  const ds = new DecompressionStream('gzip');
  const writer = ds.writable.getWriter();
  // Both writer promises reject when the stream errors on malformed input. We swallow them here
  // and let the READER surface the single authoritative error; otherwise Node reports an
  // unhandled rejection and kills the process instead of failing this one verification.
  void writer.write(compressed).catch(() => undefined);
  void writer.close().catch(() => undefined);

  const reader = ds.readable.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value === undefined) continue;
      total += value.length;
      if (total > MAX_STATUS_LIST_BYTES) {
        await reader.cancel().catch(() => undefined);
        throw new StatusListError(
          `status list expands past the ${MAX_STATUS_LIST_BYTES}-byte ceiling; refusing to decompress further`,
        );
      }
      chunks.push(value);
    }
  } catch (e) {
    if (e instanceof StatusListError) throw e;
    throw new StatusListError(`status list is not valid GZIP: ${String((e as Error)?.message ?? e)}`);
  }
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.length;
  }
  return out;
}

/** GZIP compression, same reasoning as `gunzip`. Only used by `encodeStatusList`. */
async function gzip(raw: Uint8Array): Promise<Uint8Array> {
  if (typeof CompressionStream !== 'function') {
    throw new StatusListError('CompressionStream("gzip") is unavailable in this runtime');
  }
  const cs = new CompressionStream('gzip');
  const writer = cs.writable.getWriter();
  void writer.write(raw).catch(() => undefined);
  void writer.close().catch(() => undefined);
  const reader = cs.readable.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (value === undefined) continue;
    chunks.push(value);
    total += value.length;
  }
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.length;
  }
  return out;
}

/* -------------------------------------------------------------------------- */
/* Bit access                                                                  */
/* -------------------------------------------------------------------------- */

/**
 * Read one bit of the bitstring, spec order.
 *
 * §2.2: "The bitstring MUST be encoded such that the first index, with a value of zero (0), is
 * located at the LEFT-MOST bit in the bitstring and the last index ... is located at the
 * RIGHT-MOST bit." Left-most bit of a byte is the most significant one, so index i lives at
 * `bits[i >> 3] & (0x80 >> (i & 7))`. Getting this backwards is the exact bug §7.1 warns about.
 */
export function bitAt(bits: Uint8Array, bitIndex: number): 0 | 1 {
  if (!Number.isInteger(bitIndex) || bitIndex < 0 || bitIndex >= bits.length * 8) {
    throw new StatusListError(`bit index ${bitIndex} is outside the bitstring`);
  }
  const byte = bits[bitIndex >> 3] as number;
  return ((byte >> (7 - (bitIndex & 7))) & 1) as 0 | 1;
}

/** Set one bit, same ordering as `bitAt`. Used by `encodeStatusList`. */
function setBit(bits: Uint8Array, bitIndex: number): void {
  if (!Number.isInteger(bitIndex) || bitIndex < 0 || bitIndex >= bits.length * 8) {
    throw new StatusListError(`bit index ${bitIndex} is outside the bitstring`);
  }
  bits[bitIndex >> 3] = (bits[bitIndex >> 3] as number) | (0x80 >> (bitIndex & 7));
}

/**
 * §3.2 step 10: "Let status be the value in the bitstring at the position indicated by the
 * credentialIndex multiplied by the size. If the credentialIndex multiplied by the size is a
 * value outside of the range of the bitstring, a RANGE_ERROR MUST be raised."
 *
 * For `statusSize > 1` the spec does not spell out the bit order WITHIN one entry. We read it
 * most-significant-first, consistent with index 0 being the left-most bit. That choice is
 * deliberately not load-bearing: the only question this package ever asks of the result is
 * "is it zero" (§3.2 step 13: "If status is 0, set the valid key in result to true; otherwise,
 * set it to false"), and zero-ness is invariant under ANY permutation of the bits inside the
 * entry. So a wrong intra-entry order cannot flip a revoked credential to unrevoked.
 *
 * DO NOT read the returned NUMBER as a status-message code without also reading the list's
 * `statusMessage` array — the intra-entry bit order above is unspecified, so the integer is only
 * meaningful up to a permutation. `decodeStatusList` now enforces that `statusMessage` is present
 * whenever `statusSize > 1` (R5), so the table at least exists; mapping onto it is still the
 * caller's decision and this package never makes it.
 */
export function statusAt(list: DecodedStatusList, index: number): number {
  if (!Number.isInteger(index) || index < 0) {
    throw new StatusListError(`status list index ${index} must be a non-negative integer`);
  }
  const start = index * list.statusSize;
  if (start + list.statusSize > list.bitLength) {
    throw new StatusListError(
      `RANGE_ERROR: entry ${index} (bits ${start}..${start + list.statusSize - 1}) is outside a ` +
        `${list.bitLength}-bit status list`,
    );
  }
  let value = 0;
  for (let i = 0; i < list.statusSize; i++) {
    value = (value << 1) | bitAt(list.bits, start + i);
  }
  return value;
}

function normalizeStatusSize(raw: number | undefined): number {
  // §2.2: "If statusSize is not present ... then statusSize MUST be processed as 1."
  if (raw === undefined) return 1;
  // "If present, statusSize MUST be an integer greater than zero."
  if (!Number.isInteger(raw) || raw < 1) {
    throw new StatusListError(`statusSize must be an integer greater than zero, got ${String(raw)}`);
  }
  // Our own cap. Beyond 8 the entry no longer fits a byte and nothing in this system uses it;
  // refusing is safer than silently computing a number nobody has validated.
  if (raw > 8) throw new StatusListError(`statusSize ${raw} exceeds the supported maximum of 8`);
  return raw;
}

/**
 *
 *   "If `statusSize` is provided and is greater than `1`, then the property
 *    `credentialStatus.statusMessage` MUST be present."
 *   "`statusMessage` MAY be present if `statusSize` is `1`, and MUST be present if `statusSize`
 *    is greater than `1`."
 *   "The length of which MUST equal the number of possible status messages indicated by
 *    `statusSize`" — "2 elements if statusSize has 1 bit, 4 elements if statusSize has 2 bits,
 *    8 elements if statusSize has 3 bits".
 *   Each element "MUST contain the two properties described below": `status`, "a string
 *    representing the hexadecimal value of the status prefixed with `0x`", and `message`,
 *    "a string used by software developers to assist with debugging".
 *
 * `statusAt`'s result is only ever tested for zero-ness and zero-ness survives any permutation of
 * the bits inside an entry. But a multi-bit list without `statusMessage` is a list whose non-zero
 * values have no defined meaning, and the moment anyone reads `statusAt()`'s NUMBER rather than
 * code table. Refusing the list is how that stays impossible rather than merely discouraged.
 *
 * NOT enforced, deliberately: that the `status` values actually enumerate 0..2^statusSize-1
 * without duplicates. The spec's normative text pins the COUNT and the element shape; it does not
 * spell out coverage, and inventing a stricter rule than the spec states is how a verifier starts
 * rejecting conforming issuers.
 */
/**
 * Longest untrusted fragment this module will ever splice into an error message. Error `detail`
 * reaches caller logs; remote data must not be able to size them. 80 characters is enough to
 * identify a mistyped status value and nowhere near enough to be a payload.
 */
const MAX_ECHOED_DETAIL_CHARS = 80;

function clampForDetail(value: unknown): string {
  // `JSON.stringify(undefined)` is `undefined`, not `"undefined"`, and `JSON.stringify` throws on
  // a BigInt or a circular structure. Both reach here from caller-fetched remote data, so neither
  // may escape as something other than a StatusListError.
  let s: string;
  try {
    s = JSON.stringify(value) ?? String(value);
  } catch {
    s = Object.prototype.toString.call(value);
  }
  return s.length <= MAX_ECHOED_DETAIL_CHARS
    ? s
    : `${s.slice(0, MAX_ECHOED_DETAIL_CHARS)}... (${s.length} chars, truncated)`;
}

function assertStatusMessage(raw: unknown, statusSize: number): void {
  if (raw === undefined) {
    if (statusSize > 1) {
      throw new StatusListError(
        `statusMessage is REQUIRED when statusSize is greater than 1 (statusSize ${statusSize}); ` +
          `a multi-bit status list without it has no defined meaning for its non-zero values`,
      );
    }
    return;
  }
  if (!Array.isArray(raw)) {
    throw new StatusListError('statusMessage must be an array');
  }
  const expected = 2 ** statusSize;
  if (raw.length !== expected) {
    throw new StatusListError(
      `statusMessage must hold exactly ${expected} elements for statusSize ${statusSize}, ` +
        `got ${raw.length}`,
    );
  }
  for (let i = 0; i < raw.length; i++) {
    const entry: unknown = raw[i];
    if (entry === null || typeof entry !== 'object' || Array.isArray(entry)) {
      throw new StatusListError(`statusMessage[${i}] must be an object`);
    }
    const { status, message } = entry as { status?: unknown; message?: unknown };
    if (typeof status !== 'string' || !/^0x[0-9a-fA-F]+$/.test(status)) {
      // status list is caller-fetched remote data, so an unbounded echo is a log-amplification
      // primitive. Measured before this clamp: a 1,000,000-character `status` produced a
      // 1,000,074-character `VerifyResult.detail`, which lands verbatim in any caller's log.
      throw new StatusListError(
        `statusMessage[${i}].status must be a "0x"-prefixed hexadecimal string, got ` +
          `${clampForDetail(status)}`,
      );
    }
    if (typeof message !== 'string') {
      throw new StatusListError(`statusMessage[${i}].message must be a string`);
    }
  }
}

function assertKnownPurpose(purpose: string): StatusPurpose {
  if (!(STATUS_PURPOSES as readonly string[]).includes(purpose)) {
    throw new StatusListError(
      `unsupported statusPurpose "${String(purpose)}"; this verifier acts only on ` +
        `${STATUS_PURPOSES.join('/')} and refuses to treat anything else as "not revoked"`,
    );
  }
  return purpose as StatusPurpose;
}

/**
 * §3.4 Bitstring Expansion Algorithm plus the §3.2 guards that make the result safe to read.
 *
 * Throws `StatusListError` on: unknown/mismatched purpose (step 5), bad multibase, bad base64url,
 * bad GZIP, a decompression bomb, an unusable statusSize, or a list shorter than
 * `MINIMUM_STATUS_LIST_ENTRIES` (step 9). Every one of those must fail verification CLOSED —
 * a status list we cannot read is not evidence that a credential is live.
 */
export async function decodeStatusList(
  list: BitstringStatusList,
  options: DecodeStatusListOptions = {},
): Promise<DecodedStatusList> {
  if (list === null || typeof list !== 'object') {
    throw new StatusListError('status list must be an object with statusPurpose and encodedList');
  }
  const statusPurpose = assertKnownPurpose(list.statusPurpose);
  if (options.expectedPurpose !== undefined && options.expectedPurpose !== statusPurpose) {
    // §3.2 step 5.
    throw new StatusListError(
      `statusPurpose mismatch: verifier asked about "${options.expectedPurpose}" but the supplied ` +
        `list is a "${statusPurpose}" list`,
    );
  }
  const statusSize = normalizeStatusSize(list.statusSize);
  // Before the gunzip: a structurally non-conforming list is refused without spending a
  // decompression on it. R5.
  assertStatusMessage(list.statusMessage, statusSize);

  // multibase -> base64url -> gunzip, exactly the inverse of §3.3 step 3.
  const bits = await gunzip(multibaseDecode(list.encodedList));

  const bitLength = bits.length * 8;
  const entryCount = Math.floor(bitLength / statusSize);
  // §3.2 step 9. NOT padded: see the comment on MINIMUM_STATUS_LIST_ENTRIES.
  if (entryCount < MINIMUM_STATUS_LIST_ENTRIES) {
    throw new StatusListError(
      `STATUS_LIST_LENGTH_ERROR: list holds ${entryCount} entries ` +
        `(${bits.length} bytes / statusSize ${statusSize}), spec minimum is ` +
        `${MINIMUM_STATUS_LIST_ENTRIES}. A short list is a privacy leak, so it is rejected ` +
        `rather than padded.`,
    );
  }
  return { statusPurpose, statusSize, bits, bitLength, entryCount };
}

/**
 * Convenience: decode and answer the one question a verifier has.
 * §3.2 step 13 — "If status is 0, set the valid key in result to true; otherwise, set it to false."
 */
export async function isStatusSet(
  list: BitstringStatusList,
  index: number,
  options: DecodeStatusListOptions = {},
): Promise<boolean> {
  return statusAt(await decodeStatusList(list, options), index) !== 0;
}

export interface EncodeStatusListOptions {
  readonly statusPurpose: StatusPurpose;
  /** Indices whose status bit is set (revoked / suspended). */
  readonly set?: readonly number[];
  /** Entry count. Defaults to, and may not be below, MINIMUM_STATUS_LIST_ENTRIES. */
  readonly entries?: number;
  readonly statusSize?: number;
}

/**
 * §3.3 Bitstring Generation Algorithm. Present so the gateway (and the tests) can BUILD a list
 * with the same code that reads one — an encoder and decoder that disagree about bit order is the
 * classic way this feature ships broken. Not used by verification.
 */
export async function encodeStatusList(
  options: EncodeStatusListOptions,
): Promise<BitstringStatusList> {
  const statusPurpose = assertKnownPurpose(options.statusPurpose);
  const statusSize = normalizeStatusSize(options.statusSize);
  const entries = options.entries ?? MINIMUM_STATUS_LIST_ENTRIES;
  if (!Number.isInteger(entries) || entries < MINIMUM_STATUS_LIST_ENTRIES) {
    throw new StatusListError(
      `a status list must hold at least ${MINIMUM_STATUS_LIST_ENTRIES} entries, got ${String(entries)}`,
    );
  }
  const bitLength = entries * statusSize;
  if (bitLength % 8 !== 0) {
    throw new StatusListError('entries * statusSize must be a whole number of bytes');
  }
  const bits = new Uint8Array(bitLength / 8);
  for (const idx of options.set ?? []) {
    if (!Number.isInteger(idx) || idx < 0 || idx >= entries) {
      throw new StatusListError(`index ${String(idx)} is outside a ${entries}-entry list`);
    }
    // For statusSize > 1 this sets the entry to its maximum value (all bits), which is non-zero
    // and therefore "not valid" under §3.2 step 13 regardless of intra-entry bit order.
    for (let i = 0; i < statusSize; i++) setBit(bits, idx * statusSize + i);
  }
  const encodedList = MULTIBASE_BASE64URL_NOPAD_PREFIX + base64urlEncode(await gzip(bits));
  if (statusSize === 1) return { statusPurpose, encodedList };
  // §2.2 makes statusMessage MANDATORY above one bit, and `decodeStatusList` now enforces it
  // (R5). An encoder that emitted a list its own decoder refuses would be the exact
  // encoder/decoder disagreement this module exists to prevent, so emit a conforming default:
  // 2^statusSize entries, entry 0 being the "valid" state and every other value distinguished
  // only by its index. A real issuer overrides these strings with meaningful ones.
  const statusMessage: StatusMessage[] = Array.from({ length: 2 ** statusSize }, (_, v) => ({
    status: `0x${v.toString(16)}`,
    message:
      v === 0 ? 'valid' : `${statusPurpose === 'suspension' ? 'suspended' : 'revoked'} (code ${v})`,
  }));
  return { statusPurpose, encodedList, statusSize, statusMessage };
}
