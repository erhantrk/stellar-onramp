/**
 * Presentation binding.
 *
 * A BBS+ proof on its own is a statement about a signature — it says nothing about *where* it
 * may be spent. `presentationHeader` is the only channel through which context enters the
 *
 * The design rule this module enforces: THERE IS NO WAY TO PRODUCE A PROOF WITHOUT A BINDING.
 * `derive()` takes a `ProofBinding` as a required positional argument and computes the
 * presentation header itself; the raw `presentationHeader` bytes are never accepted from a
 * caller. A caller cannot "forget" to bind, and cannot bind to something we did not canonicalise.
 */

import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, utf8ToBytes, concatBytes } from '@noble/hashes/utils.js';

/** Domain separators. Any change is a wire-format break; the Rust verifier mirrors these. */
export const BINDING_DOMAIN = 'stellaronramp/presentation-binding/v1';
export const PRESENTATION_HEADER_DOMAIN = 'stellaronramp/presentation-header/v1';

export const NONCE_BYTES = 32;

/**
 * How far ahead of the CURRENT ledger a presentation's `ledgerExpiry` may sit, in ledgers
 * (~1 day at 5 s ledgers). Mirrors `PROOF_MAX_WINDOW` in `contracts/kyc-gate/src/lib.rs`:
 * `attest_bbs` refuses anything wider with `ExpiryTooFar`, so a proof bound further out than
 * this is simply unsubmittable and the SDK must not mint one.
 *
 * It is not checked in `assertValidBinding` — that function is a pure syntactic check with no
 * ledger view — so a caller choosing `ledgerExpiry` must clamp against it itself:
 * `ledgerExpiry = currentLedger + n`, `n <= PROOF_MAX_WINDOW`.
 *
 * WHY A CAP EXISTS AT ALL: the on-chain consumed-nonce tombstone is TEMPORARY storage and lives
 * ~1 day at minimum. A freshness window wider than the tombstone means the identical proof
 * becomes replayable the moment the tombstone is evicted — which is how a revoked subject was
 */
export const PROOF_MAX_WINDOW = 17_280;

export class BindingError extends Error {
  override readonly name = 'BindingError';
}

/**
 * Everything a proof is pinned to. All five fields are mandatory: dropping any one of them
 * re-opens a concrete replay path.
 */
export interface ProofBinding {
  /** 32-byte challenge from the relying party, lowercase hex. Anti-replay across time. */
  readonly nonce: string;
  /** Holder's smart-wallet C-address. Anti-replay across *holders*. */
  readonly walletAddress: string;
  /** `kyc-gate` contract id (C-address). Anti-replay across *contracts*. */
  readonly contractId: string;
  /** Full network passphrase, e.g. "Test SDF Network ; September 2015". Anti-cross-network. */
  readonly networkPassphrase: string;
  /** Ledger sequence after which the proof is dead. Anti-replay across *time*, on-chain. */
  readonly ledgerExpiry: number;
}

const HEX_NONCE = /^[0-9a-f]{64}$/;
// Stellar strkey: G… (classic, 56) and C… (contract, 56). Both base32, 56 chars.
const STRKEY_C = /^C[A-Z2-7]{55}$/;
const STRKEY_ANY = /^[GC][A-Z2-7]{55}$/;

export function assertValidBinding(b: ProofBinding): void {
  if (typeof b?.nonce !== 'string' || !HEX_NONCE.test(b.nonce)) {
    throw new BindingError(`binding.nonce must be ${NONCE_BYTES} bytes of lowercase hex`);
  }
  if (typeof b.walletAddress !== 'string' || !STRKEY_ANY.test(b.walletAddress)) {
    throw new BindingError('binding.walletAddress must be a Stellar C- or G-address');
  }
  if (typeof b.contractId !== 'string' || !STRKEY_C.test(b.contractId)) {
    throw new BindingError('binding.contractId must be a Stellar contract (C…) address');
  }
  if (typeof b.networkPassphrase !== 'string' || b.networkPassphrase.length === 0) {
    throw new BindingError('binding.networkPassphrase must be a non-empty string');
  }
  if (
    typeof b.ledgerExpiry !== 'number' ||
    !Number.isInteger(b.ledgerExpiry) ||
    b.ledgerExpiry < 0 ||
    b.ledgerExpiry > 0xffff_ffff
  ) {
    throw new BindingError('binding.ledgerExpiry must be a u32 ledger sequence');
  }
}

/** Cryptographically random nonce. Use this; do not hand-roll one. */
export function randomNonce(): string {
  return bytesToHex(crypto.getRandomValues(new Uint8Array(NONCE_BYTES)));
}

function lenPrefixed(field: Uint8Array): Uint8Array {
  // 4-byte big-endian length prefix on every field, so no field boundary is ambiguous and
  // ("ab","c") cannot collide with ("a","bc").
  const n = field.length;
  const header = new Uint8Array([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);
  return concatBytes(header, field);
}

function u32be(n: number): Uint8Array {
  return new Uint8Array([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);
}

/**
 * Canonical, length-prefixed serialisation of the binding.
 *
 * Layout (all fields length-prefixed with u32 big-endian):
 *   LP(nonce_bytes)                   // 32 raw bytes, not hex
 *                                          // itself uses as the network id
 *   LP(u32be(ledgerExpiry))
 */
export function canonicalBindingBytes(b: ProofBinding): Uint8Array {
  assertValidBinding(b);
  return concatBytes(
    lenPrefixed(utf8ToBytes(BINDING_DOMAIN)),
    lenPrefixed(hexToBytes(b.nonce)),
    lenPrefixed(utf8ToBytes(b.walletAddress)),
    lenPrefixed(utf8ToBytes(b.contractId)),
    lenPrefixed(sha256(utf8ToBytes(b.networkPassphrase))),
    lenPrefixed(u32be(b.ledgerExpiry)),
  );
}

/** sha256 over the canonical bytes. Stable id for a binding; also the replay-guard key. */
export function bindingDigest(b: ProofBinding): Uint8Array {
  return sha256(canonicalBindingBytes(b));
}

export function bindingDigestHex(b: ProofBinding): string {
  return bytesToHex(bindingDigest(b));
}

/**
 * The BBS+ `presentationHeader`. Domain-separated from `bindingDigest` so the two can never be
 * confused for one another on the wire.
 */
export function presentationHeaderFor(b: ProofBinding): Uint8Array {
  return sha256(concatBytes(utf8ToBytes(PRESENTATION_HEADER_DOMAIN), bindingDigest(b)));
}

export function bindingsEqual(a: ProofBinding, b: ProofBinding): boolean {
  const x = bindingDigest(a);
  const y = bindingDigest(b);
  // Constant-time-ish; these are public digests, but avoid leaking a prefix-match oracle.
  let diff = x.length ^ y.length;
  for (let i = 0; i < Math.min(x.length, y.length); i++) diff |= (x[i] ?? 0) ^ (y[i] ?? 0);
  return diff === 0;
}

/**
 * In-memory single-use nonce enforcement.
 *
 * BBS+ gives unlinkability, which means the *proof bytes* differ every time even for the same
 * credential — so proof-bytes deduplication catches nothing. Replay must be caught on the
 * off-chain (gateway, tests) this class is the equivalent.
 */
export class ReplayGuard {
  readonly #consumed = new Set<string>();

  /** Marks the binding used. Returns false if it was already consumed. */
  consume(binding: ProofBinding): boolean {
    const key = bindingDigestHex(binding);
    if (this.#consumed.has(key)) return false;
    this.#consumed.add(key);
    return true;
  }

  has(binding: ProofBinding): boolean {
    return this.#consumed.has(bindingDigestHex(binding));
  }

  get size(): number {
    return this.#consumed.size;
  }

  clear(): void {
    this.#consumed.clear();
  }
}
