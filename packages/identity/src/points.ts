/**
 *
 * BBS+ serialises G1 as 48 compressed bytes and G2 as 96. The Soroban host REJECTS the
 * compression flag (`bls12_381.rs:158`, CAP-0059: "The compression flag (the most significant
 * bit) is set" → error) and ships NO decompression host function — `grep -rn
 * 'decompress|deserialize_compressed'` across the whole host crate returns zero hits.
 *
 * So decompression is unavoidably the client SDK's job. This is safe: the host still validates
 * on-curve and subgroup membership, so a wrong Y-sign is caught, it just fails the proof.
 *
 * SOROBAN WIRE LAYOUT — the Rust verifier depends on this exactly:
 *   G1, 96 bytes:  be(X) ‖ be(Y)                              (two 48-byte big-endian Fp)
 *   G2, 192 bytes: be(X_c1) ‖ be(X_c0) ‖ be(Y_c1) ‖ be(Y_c0)  (four 48-byte big-endian Fp)
 * No flag bits, no padding. Note the c1-before-c0 ordering on G2 — it matches the zcash/IETF
 * uncompressed convention, and getting it backwards produces a point that is still on the curve
 * often enough to be a genuinely nasty bug.
 */

import { bls12_381 } from '@noble/curves/bls12-381.js';
import { bytesToHex } from '@noble/hashes/utils.js';

import { MAX_SCHEMA_ATTRIBUTES } from './schema.js';

export const G1_COMPRESSED_BYTES = 48;
export const G1_UNCOMPRESSED_BYTES = 96;
export const G2_COMPRESSED_BYTES = 96;
export const G2_UNCOMPRESSED_BYTES = 192;
export const SCALAR_BYTES = 32;
/** Fp element width; 381 bits rounded to 48 bytes. */
export const FP_BYTES = 48;

export class PointError extends Error {
  override readonly name = 'PointError';
}

function fpToBe(x: bigint): Uint8Array {
  if (x < 0n) throw new PointError('negative Fp coordinate');
  const out = new Uint8Array(FP_BYTES);
  let v = x;
  for (let i = FP_BYTES - 1; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  if (v !== 0n) throw new PointError('Fp coordinate exceeds 48 bytes');
  return out;
}

/** 48-byte compressed G1 → 96-byte Soroban form `be(X) ‖ be(Y)`. */
export function decompressG1(compressed: Uint8Array): Uint8Array {
  if (compressed.length !== G1_COMPRESSED_BYTES) {
    throw new PointError(`G1 compressed point must be ${G1_COMPRESSED_BYTES} bytes`);
  }
  const point = bls12_381.G1.Point.fromBytes(compressed);
  point.assertValidity();
  const { x, y } = point.toAffine();
  const out = new Uint8Array(G1_UNCOMPRESSED_BYTES);
  out.set(fpToBe(x), 0);
  out.set(fpToBe(y), FP_BYTES);
  return out;
}

/** 96-byte compressed G2 → 192-byte Soroban form `be(X_c1) ‖ be(X_c0) ‖ be(Y_c1) ‖ be(Y_c0)`. */
export function decompressG2(compressed: Uint8Array): Uint8Array {
  if (compressed.length !== G2_COMPRESSED_BYTES) {
    throw new PointError(`G2 compressed point must be ${G2_COMPRESSED_BYTES} bytes`);
  }
  const point = bls12_381.G2.Point.fromBytes(compressed);
  point.assertValidity();
  const { x, y } = point.toAffine();
  const out = new Uint8Array(G2_UNCOMPRESSED_BYTES);
  out.set(fpToBe(x.c1), 0);
  out.set(fpToBe(x.c0), FP_BYTES);
  out.set(fpToBe(y.c1), 2 * FP_BYTES);
  out.set(fpToBe(y.c0), 3 * FP_BYTES);
  return out;
}

/** Inverse, for round-trip tests and for reading anything that came back off-chain. */
export function compressG1(uncompressed: Uint8Array): Uint8Array {
  if (uncompressed.length !== G1_UNCOMPRESSED_BYTES) {
    throw new PointError(`G1 uncompressed point must be ${G1_UNCOMPRESSED_BYTES} bytes`);
  }
  const x = beToBigint(uncompressed.subarray(0, FP_BYTES));
  const y = beToBigint(uncompressed.subarray(FP_BYTES));
  return bls12_381.G1.Point.fromAffine({ x, y }).toBytes(true);
}

export function compressG2(uncompressed: Uint8Array): Uint8Array {
  if (uncompressed.length !== G2_UNCOMPRESSED_BYTES) {
    throw new PointError(`G2 uncompressed point must be ${G2_UNCOMPRESSED_BYTES} bytes`);
  }
  const xc1 = beToBigint(uncompressed.subarray(0, FP_BYTES));
  const xc0 = beToBigint(uncompressed.subarray(FP_BYTES, 2 * FP_BYTES));
  const yc1 = beToBigint(uncompressed.subarray(2 * FP_BYTES, 3 * FP_BYTES));
  const yc0 = beToBigint(uncompressed.subarray(3 * FP_BYTES));
  const Fp2 = bls12_381.fields.Fp2;
  return bls12_381.G2.Point.fromAffine({
    x: Fp2.create({ c0: xc0, c1: xc1 }),
    y: Fp2.create({ c0: yc0, c1: yc1 }),
  }).toBytes(true);
}

function beToBigint(bytes: Uint8Array): bigint {
  let v = 0n;
  for (const b of bytes) v = (v << 8n) | BigInt(b);
  return v;
}

/* -------------------------------------------------------------------------- */
/* BBS+ wire structures                                                        */
/* -------------------------------------------------------------------------- */

/** `signature_octets = A (48, compressed G1) ‖ e (32, scalar)`. Total 80. */
export const SIGNATURE_BYTES = G1_COMPRESSED_BYTES + SCALAR_BYTES;

export interface SorobanSignature {
  /** 96-byte uncompressed G1. */
  readonly a: Uint8Array;
  /** 32-byte big-endian scalar mod r. */
  readonly e: Uint8Array;
}

export function splitSignature(signature: Uint8Array): SorobanSignature {
  if (signature.length !== SIGNATURE_BYTES) {
    throw new PointError(`BBS+ signature must be ${SIGNATURE_BYTES} bytes`);
  }
  return {
    a: decompressG1(signature.subarray(0, G1_COMPRESSED_BYTES)),
    e: signature.slice(G1_COMPRESSED_BYTES),
  };
}

/**
 * `U > MAX_SCHEMA_ATTRIBUTES` is refused here, and this is the ONLY place it is refused.
 *
 * `cpu(N) = 41,980,626 + 1,471,918·N` and N = 40 busts both the "under 100 M instructions" and
 * "under 25 % of the 400 M budget" bounds. `MAX_SCHEMA_ATTRIBUTES` recorded that number and
 * so a 32 KB byte string decoded to U = 1,014 and `splitProof` happily allocated 1,014 scalars.
 *
 * The bound is on N = R + U, and these two functions only ever see U — but `U <= N`, so `U > 39`
 * is unconditionally illegal and is the strongest statement available without a schema in hand.
 * `verifyDetailed` pins the rest (`totalMessages === SCHEMA_ATTRIBUTE_COUNT`, then
 * `U === N - R`), which is why this is unreachable at N = 12 and is here for schema v2.
 */
function assertUndisclosedCountInRange(u: number, what: string): void {
  if (u > MAX_SCHEMA_ATTRIBUTES) {
    throw new PointError(
      `${what}: U=${u} exceeds MAX_SCHEMA_ATTRIBUTES ${MAX_SCHEMA_ATTRIBUTES}. ` +
        'A schema that large costs more than 100M instructions to verify on chain, so no proof ' +
        'over it can be attested.',
    );
  }
}

/**
 * messages. It decomposes as 3 compressed G1 points (3×48 = 144) plus `4 + U` scalars:
 * ê, r1̂, r3̂, then U hidden-message responses m̂_j, then the challenge c.
 */
export function expectedProofBytes(undisclosedCount: number): number {
  if (!Number.isInteger(undisclosedCount) || undisclosedCount < 0) {
    throw new PointError('undisclosedCount must be a non-negative integer');
  }
  assertUndisclosedCountInRange(undisclosedCount, 'expectedProofBytes');
  return 144 + SCALAR_BYTES * (4 + undisclosedCount);
}

/** Number of undisclosed messages implied by a proof's length. */
export function undisclosedCountFromProofBytes(length: number): number {
  const floor = 3 * G1_COMPRESSED_BYTES + 4 * SCALAR_BYTES; // 144 + 128 = 272
  if (length < floor || (length - floor) % SCALAR_BYTES !== 0) {
    throw new PointError(`invalid BBS+ proof length ${length}`);
  }
  const u = (length - floor) / SCALAR_BYTES;
  assertUndisclosedCountInRange(u, `invalid BBS+ proof length ${length}`);
  return u;
}

/**
 * Proof, decomposed and decompressed for Soroban.
 *
 * Wire order in the compressed proof (`proof_to_octets`, draft-irtf-cfrg-bbs-signatures §4.2 —
 * confirmed by reading @digitalbazaar/bbs-signatures lib/bbs/util.js):
 *   Abar(48) ‖ Bbar(48) ‖ D(48) ‖ ê(32) ‖ r1̂(32) ‖ r3̂(32) ‖ m̂_1..m̂_U(32·U) ‖ c(32)
 * The challenge is LAST, after the hidden-message responses — not third as a naive reading of
 * "4 scalars then U" would suggest.
 */
export interface SorobanProof {
  /** 96-byte uncompressed G1. */
  readonly abar: Uint8Array;
  /** 96-byte uncompressed G1. */
  readonly bbar: Uint8Array;
  /** 96-byte uncompressed G1. */
  readonly d: Uint8Array;
  readonly eHat: Uint8Array;
  readonly r1Hat: Uint8Array;
  readonly r3Hat: Uint8Array;
  /** U responses, in ascending hidden-index order. */
  readonly mHat: readonly Uint8Array[];
  readonly challenge: Uint8Array;
  readonly undisclosedCount: number;
}

export function splitProof(proof: Uint8Array): SorobanProof {
  const u = undisclosedCountFromProofBytes(proof.length);
  let off = 0;
  const takePoint = (): Uint8Array => {
    const p = decompressG1(proof.subarray(off, off + G1_COMPRESSED_BYTES));
    off += G1_COMPRESSED_BYTES;
    return p;
  };
  const takeScalar = (): Uint8Array => {
    const s = proof.slice(off, off + SCALAR_BYTES);
    off += SCALAR_BYTES;
    return s;
  };
  const abar = takePoint();
  const bbar = takePoint();
  const d = takePoint();
  const eHat = takeScalar();
  const r1Hat = takeScalar();
  const r3Hat = takeScalar();
  const mHat: Uint8Array[] = [];
  for (let i = 0; i < u; i++) mHat.push(takeScalar());
  const challenge = takeScalar();
  return { abar, bbar, d, eHat, r1Hat, r3Hat, mHat, challenge, undisclosedCount: u };
}

/**
 * Flat Soroban-ready proof blob: the three G1 points uncompressed, then the scalars in wire
 * order. Length = `288 + 32·(4 + U)` (144 bytes larger than the compressed proof).
 */
export function flattenSorobanProof(p: SorobanProof): Uint8Array {
  const out = new Uint8Array(
    3 * G1_UNCOMPRESSED_BYTES + SCALAR_BYTES * (4 + p.undisclosedCount),
  );
  let off = 0;
  for (const chunk of [p.abar, p.bbar, p.d, p.eHat, p.r1Hat, p.r3Hat, ...p.mHat, p.challenge]) {
    out.set(chunk, off);
    off += chunk.length;
  }
  return out;
}

export function toHex(bytes: Uint8Array): string {
  return bytesToHex(bytes);
}
