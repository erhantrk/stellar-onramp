/**
 * The BBS+ message generators, DERIVED — the thing `GET /v1/.well-known/issuer` could not emit.
 *
 * WHY THIS FILE IS NOT A LIST OF CONSTANTS. The generators are the L+1 = 13 G1 points every party
 * to a proof must agree on, and the on-chain verifier computes them itself, from nothing but the
 * ciphersuite's domain-separation tags (`contracts/kyc-gate/src/bbs.rs::create_generators`). That
 * is deliberate: they are the only public parameters in the system that a prover could otherwise
 * try to substitute, and a value re-derived from constants has no argument left to get wrong.
 * Publishing them is therefore a CONVENIENCE for an off-chain verifier, never an input to one —
 * anything that treats a published generator set as authoritative has reintroduced exactly the
 * substitution the contract refuses to allow.
 *
 * So this file re-derives them the same way rather than pasting hex, and
 * `test/generators.test.ts` pins the output three ways: against the frozen `Q1_UNCOMPRESSED`
 * constant read out of the Rust source, against the 13 values `create_generators` produces
 * (asserted on the Rust side too, in `bbs_generators_match_the_typescript_export`), and against
 * `@digitalbazaar/bbs-signatures`' own `create_generators`, which is the library that produced
 * `fixtures/vectors.json` and therefore the arbiter of what the signatures were made against.
 *
 * ALGORITHM (draft-irtf-cfrg-bbs-signatures-08 `create_generators`, as implemented by
 * `@digitalbazaar/bbs-signatures@3.1.0` `lib/bbs/util.js`):
 *
 *     v = expand_message_xmd(generator_seed, seed_dst, 48)
 *     for i in 1..=count:
 *         v = expand_message_xmd(v || I2OSP(i, 8), seed_dst, 48)
 *         generator_i = hash_to_curve_g1(v, generator_dst)
 *
 * `I2OSP(i, 8)` is EIGHT bytes big-endian, not the 4-byte native width — the same bit-exact wire
 * detail `bbs.rs` calls out. The reference library is not importable here (its `exports` map has
 * no subpath, `import('@digitalbazaar/bbs-signatures/lib/bbs/util.js')` is
 * `ERR_PACKAGE_PATH_NOT_EXPORTED`), which is why the algorithm is restated over `@noble/curves`
 * rather than delegated, and why the test cross-checks against it by file path.
 */

import { bls12_381 } from '@noble/curves/bls12-381.js';
import { expand_message_xmd } from '@noble/curves/abstract/hash-to-curve.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, concatBytes, utf8ToBytes } from '@noble/hashes/utils.js';

import { SCHEMA_ATTRIBUTE_COUNT } from './schema.js';

export class GeneratorError extends Error {
  override readonly name = 'GeneratorError';
}

/**
 * `api_id = ciphersuite_id || CORE_API_ID`, and its three suffixes. Byte-for-byte the constants in
 * `contracts/kyc-gate/src/bbs.rs` (`API_ID`, `GENERATOR_SEED`, `SEED_DST`, `GENERATOR_DST`) — if
 * these two lists ever disagree the on-chain verifier and this package are computing different
 * generators and every proof stops verifying on one side or the other.
 */
export const BBS_API_ID = 'BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_';
const GENERATOR_SEED = utf8ToBytes(`${BBS_API_ID}MESSAGE_GENERATOR_SEED`);
const SEED_DST = utf8ToBytes(`${BBS_API_ID}SIG_GENERATOR_SEED_`);
const GENERATOR_DST = utf8ToBytes(`${BBS_API_ID}SIG_GENERATOR_DST_`);

/** `expand_len` for BLS12-381-SHA-256: 48 bytes. */
const EXPAND_LEN = 48;

/**
 * L + 1: one `Q_1` plus one `H_i` per message. 13 for the frozen 12-attribute schema, and the
 * count `bbs.rs::create_generators` hard-codes as `SCHEMA_MESSAGE_COUNT + 1`.
 */
export const BBS_GENERATOR_COUNT = SCHEMA_ATTRIBUTE_COUNT + 1;

/** `I2OSP(i, 8)` — eight bytes, big-endian. */
function i2osp8(i: number): Uint8Array {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, BigInt(i));
  return out;
}

/**
 * The raw derivation. Exported so a schema v2 with a different L can ask for its own count
 * without this module needing to know about it.
 */
export function createGenerators(count: number = BBS_GENERATOR_COUNT): Uint8Array[] {
  if (!Number.isInteger(count) || count < 1) {
    throw new GeneratorError(`generator count must be an integer >= 1, got ${count}`);
  }
  let v = expand_message_xmd(GENERATOR_SEED, SEED_DST, EXPAND_LEN, sha256);
  const out: Uint8Array[] = [];
  for (let i = 1; i <= count; i++) {
    v = expand_message_xmd(concatBytes(v, i2osp8(i)), SEED_DST, EXPAND_LEN, sha256);
    // Uncompressed `be(X) || be(Y)`, 96 bytes, no 0x04 prefix — the Soroban `Bls12381G1Affine`
    // wire form, identical to what `to_array()` yields on the Rust side.
    out.push(bls12_381.G1.hashToCurve(v, { DST: GENERATOR_DST }).toBytes(false));
  }
  return out;
}

export interface BbsGenerators {
  /** L + 1. */
  readonly count: number;
  /** 96-byte `be(X) ‖ be(Y)` hex, the Soroban wire form. `generators_root` hashes THESE. */
  readonly uncompressed: readonly string[];
  /** 48-byte hex, the BBS+/`@noble` wire form, for a verifier using an off-chain library. */
  readonly compressed: readonly string[];
  /** {@link GENERATORS_ROOT_ENCODING}. */
  readonly root: string;
}

/**
 * WHAT `generators_root` IS, stated once and pinned, because the spec sentence is one clause long
 * "canonical" is doing all the work.
 *
 * It is `sha256` over the 13 generators concatenated in index order, each in its 96-byte
 * UNCOMPRESSED `be(X) ‖ be(Y)` form. 1,248 bytes in, 32 out.
 *
 * WHY UNCOMPRESSED — and NOT because "a contract cannot recompute the compressed form", which is
 * G1 in pure byte arithmetic with no host call — `contracts/kyc-gate/src/bbs.rs::g1_compress` —
 * and `calculate_domain` already hashes the COMPRESSED generators on every `attest_bbs`. What
 * decompression buys nothing for is the INPUT side: the host rejects the compression flag, so
 * points arrive uncompressed and only ever go the other way.
 *
 * `generators: Vec<Bls12381G1Affine>` — uncompressed, its step 3 refuses a 48-byte compressed
 * point outright — so the bytes step 2 has in hand are the uncompressed ones, and a root defined
 * over them is computable from the argument without re-serialising it. `kyc-registry` stores
 * `pk_g2` uncompressed for the same reason.
 *
 * THE REJECTED ALTERNATIVE, named so it is visibly considered rather than missed: the BBS
 * `serialize()` / `dom_octs` encoding `bbs.rs::calculate_domain` builds, `I2OSP(L, 8) ‖ 13
 * compressed generators`. That is the in-repo precedent for "canonical L+1 generator encoding"
 * and the reading a `kyc-registry` implementer is most likely to reach for. It hashes to
 * `524451dfde46907f1445c3a22359578426f1762a02e15edec879d130250199c0` (measured, L = 12 to match
 * `SCHEMA_MESSAGE_COUNT`); the same 13 compressed points concatenated WITHOUT the length prefix
 * hash to `bd40396e37860601a72ebed0b9351a86c99ead181b10605f19afa4f94f2a6d8c`. Neither is what
 * this constant means, all three digests are 32 self-describing-nothing bytes, and guessing wrong
 * is silent — which is why the encoding is published alongside the root in
 * `GET /v1/.well-known/issuer` rather than left to be inferred.
 *
 * NOTHING ON CHAIN COMPUTES THIS TODAY. `kyc-gate` re-derives the generators and never reads a
 * root; `kyc-registry`, which is where the field lives, is spec-only. So this is a wire format
 * being LANDED, not one being matched, and the pin that makes it real is the pair of tests —
 * `test/generators.test.ts` here and `bbs_generators_match_the_typescript_export` in
 * `contracts/kyc-gate/src/test.rs`, which recomputes the same 32 bytes from the contract's own
 * `create_generators` through the contract's own `env.crypto().sha256`. Whoever writes
 * `kyc-registry` inherits the definition with a failing test attached if they deviate.
 */
export const GENERATORS_ROOT_ENCODING =
  'sha256(g_1 ‖ … ‖ g_{L+1}), each g_i the 96-byte uncompressed be(X) ‖ be(Y)';

let cached: BbsGenerators | undefined;

/**
 * The frozen schema's generator set. Memoised: the derivation is 13 hash-to-curve operations
 * (~10 ms) and the answer is a constant of the ciphersuite, not of any issuer — every issuer on
 * schema v1 publishes the identical set, and that is expected, not a bug.
 *
 * FROZEN, not just `readonly`. Memoising makes this process-global state, and `readonly` is a
 * compile-time fiction: before this, `bbsGenerators().uncompressed[0] = 'x'` in any module
 * permanently changed what every later call — and therefore what `GET /v1/.well-known/issuer`
 * TypeError in strict mode (every ESM module is strict) instead of a silent poisoning.
 */
export function bbsGenerators(): BbsGenerators {
  if (cached === undefined) {
    const points = createGenerators(BBS_GENERATOR_COUNT);
    cached = Object.freeze({
      count: BBS_GENERATOR_COUNT,
      uncompressed: Object.freeze(points.map((p) => bytesToHex(p))),
      compressed: Object.freeze(
        points.map((p) => bytesToHex(bls12_381.G1.Point.fromBytes(p).toBytes(true))),
      ),
      root: bytesToHex(sha256(concatBytes(...points))),
    });
  }
  return cached;
}
