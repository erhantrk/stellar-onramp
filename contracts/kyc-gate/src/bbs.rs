//! The on-chain BBS+ selective-disclosure verifier, written directly against the BLS12-381
//! host functions (CAP-0059 / Protocol 22+). No pure-wasm pairing library is pulled in: a single
//! pure-wasm pairing measured 874,530,454 instructions, 2.2x over the whole 400 M budget.
//!
//! This module reproduces `@digitalbazaar/bbs-signatures@3.1.0` `ProofVerify` bit-for-bit so the
//! frozen `gate-onramp` known-answer vector (packages/identity/fixtures/vectors.json) verifies.
//! The reference is the OFF-CHAIN library that produced the frozen vectors, so its
//! `create_generators` seed/DST, `calculate_domain` and `hash_to_scalar` (the 384-bit -> mod-r
//! reduction) are what this code mirrors, not the IETF draft's prose.
//!
//! Everything here is a FREE function on `Env`; the `#[contract]` surface lives in `lib.rs` and
//! calls `verify_bbs_proof`.

use soroban_sdk::crypto::bls12_381::{Bls12381Fr, Bls12381G1Affine, Bls12381G2Affine};
use soroban_sdk::{Bytes, BytesN, Env, U256, Vec};

use crate::BbsProof;

// -------------------------------------------------------------------------------------------
// Domain-separation constants. These are the exact `api_id` and its DST suffixes from
// `@digitalbazaar/bbs-signatures/lib/bbs/{constants,util,ciphersuites}.js`, for the
// `BLS12381_SHA256` ciphersuite (`BLS_BLS12381G1_XMD:SHA-256_SSWU_RO_`).
//
//   api_id              = ciphersuite_id || CORE_API_ID
//                        = "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_" || "H2G_HM2S_"
//   seed_dst            = api_id || "SIG_GENERATOR_SEED_"       (19 B)
//   generator_dst       = api_id || "SIG_GENERATOR_DST_"        (18 B)
//   generator_seed      = api_id || "MESSAGE_GENERATOR_SEED"    (22 B)
//   map_dst             = api_id || "MAP_MSG_TO_SCALAR_AS_HASH_" (26 B)
//   hash_to_scalar_dst  = api_id || "H2S_"                       (4 B)
// -------------------------------------------------------------------------------------------
const API_ID: &[u8] = b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_";
const GENERATOR_SEED: &[u8] =
    b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_MESSAGE_GENERATOR_SEED";
const SEED_DST: &[u8] =
    b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_SIG_GENERATOR_SEED_";
const GENERATOR_DST: &[u8] =
    b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_SIG_GENERATOR_DST_";
const MAP_DST: &[u8] =
    b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_MAP_MSG_TO_SCALAR_AS_HASH_";
const H2S_DST: &[u8] = b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_H2S_";

/// The BBS ciphersuite's `P1` fixed generator (uncompressed G1), from
/// `ciphersuites.js` `BLS12381_SHA256.P1`. Hard-coded because there is no decompression host
/// function, and `P1` is a fixed derivation constant (not a party-chosen input).
const P1_UNCOMPRESSED: [u8; 96] = [
    0x08, 0xce, 0x25, 0x61, 0x02, 0x84, 0x08, 0x21, 0xa3, 0xe9, 0x4e, 0xa9, 0x02, 0x5e, 0x46, 0x62,
    0xb2, 0x05, 0x76, 0x2f, 0x97, 0x76, 0xb3, 0xa7, 0x66, 0xc8, 0x72, 0xb9, 0x48, 0xf1, 0xfd, 0x22,
    0x5e, 0x7c, 0x59, 0x69, 0x85, 0x88, 0xe7, 0x0d, 0x11, 0x40, 0x6d, 0x16, 0x1b, 0x4e, 0x28, 0xc9,
    0x10, 0xa7, 0x11, 0xac, 0xd1, 0x6f, 0xf4, 0x3e, 0x30, 0xb3, 0x37, 0x3b, 0x7b, 0x6a, 0x92, 0x33,
    0x94, 0x5e, 0xc7, 0x4a, 0xdf, 0x00, 0xb0, 0x48, 0x1f, 0xbc, 0xd5, 0xe3, 0xb1, 0xe3, 0x42, 0xe7,
    0xa1, 0x05, 0xb4, 0x96, 0x61, 0x95, 0xe6, 0xa6, 0x78, 0x85, 0x7a, 0x0e, 0x04, 0x93, 0xd5, 0xb1,
];

/// The BLS12-381 G2 generator `BP2` (uncompressed, `be(X_c1) || be(X_c0) || be(Y_c1) || be(Y_c0)`).
/// Used negated in the pairing check `e(Abar, W) * e(Bbar, -BP2) == 1_GT`.
const P2_UNCOMPRESSED: [u8; 192] = [
    0x13, 0xe0, 0x2b, 0x60, 0x52, 0x71, 0x9f, 0x60, 0x7d, 0xac, 0xd3, 0xa0, 0x88, 0x27, 0x4f, 0x65,
    0x59, 0x6b, 0xd0, 0xd0, 0x99, 0x20, 0xb6, 0x1a, 0xb5, 0xda, 0x61, 0xbb, 0xdc, 0x7f, 0x50, 0x49,
    0x33, 0x4c, 0xf1, 0x12, 0x13, 0x94, 0x5d, 0x57, 0xe5, 0xac, 0x7d, 0x05, 0x5d, 0x04, 0x2b, 0x7e,
    0x02, 0x4a, 0xa2, 0xb2, 0xf0, 0x8f, 0x0a, 0x91, 0x26, 0x08, 0x05, 0x27, 0x2d, 0xc5, 0x10, 0x51,
    0xc6, 0xe4, 0x7a, 0xd4, 0xfa, 0x40, 0x3b, 0x02, 0xb4, 0x51, 0x0b, 0x64, 0x7a, 0xe3, 0xd1, 0x77,
    0x0b, 0xac, 0x03, 0x26, 0xa8, 0x05, 0xbb, 0xef, 0xd4, 0x80, 0x56, 0xc8, 0xc1, 0x21, 0xbd, 0xb8,
    0x06, 0x06, 0xc4, 0xa0, 0x2e, 0xa7, 0x34, 0xcc, 0x32, 0xac, 0xd2, 0xb0, 0x2b, 0xc2, 0x8b, 0x99,
    0xcb, 0x3e, 0x28, 0x7e, 0x85, 0xa7, 0x63, 0xaf, 0x26, 0x74, 0x92, 0xab, 0x57, 0x2e, 0x99, 0xab,
    0x3f, 0x37, 0x0d, 0x27, 0x5c, 0xec, 0x1d, 0xa1, 0xaa, 0xa9, 0x07, 0x5f, 0xf0, 0x5f, 0x79, 0xbe,
    0x0c, 0xe5, 0xd5, 0x27, 0x72, 0x7d, 0x6e, 0x11, 0x8c, 0xc9, 0xcd, 0xc6, 0xda, 0x2e, 0x35, 0x1a,
    0xad, 0xfd, 0x9b, 0xaa, 0x8c, 0xbd, 0xd3, 0xa7, 0x6d, 0x42, 0x9a, 0x69, 0x51, 0x60, 0xd1, 0x2c,
    0x92, 0x3a, 0xc9, 0xcc, 0x3b, 0xac, 0xa2, 0x89, 0xe1, 0x93, 0x54, 0x86, 0x08, 0xb8, 0x28, 0x01,
];

/// `2^256 mod r` — the single constant that lets a 384-bit `expand_message_xmd` output be reduced
/// modulo the scalar field order `r` using two 32-byte limbs and one `fr_mul` + one `fr_add`. The
/// 48-byte uniform string `U` is split `U = hi·2^256 + lo` (hi = first 16 B, lo = last 32 B); then
/// `U mod r = hi·C256 + lo (mod r)`, where `lo` is reduced by `Bls12381Fr::from_bytes` and `hi` is
/// already `< r`. This is the two-limb reduction the spec flags as its #1 soundness-bug spot
const C256_MOD_R: [u8; 32] = [
    0x18, 0x24, 0xb1, 0x59, 0xac, 0xc5, 0x05, 0x6f, 0x99, 0x8c, 0x4f, 0xef, 0xec, 0xbc, 0x4f, 0xf5,
    0x58, 0x84, 0xb7, 0xfa, 0x00, 0x03, 0x48, 0x02, 0x00, 0x00, 0x00, 0x01, 0xff, 0xff, 0xff, 0xfe,
];

/// `(p-1)/2` where `p` is the BLS12-381 base-field modulus — the threshold a coordinate is compared
/// against to recover the compressed-form "sort" bit (`sort = y > (p-1)/2`, the zcash/IETF
/// convention used by `@noble/curves` `toBytes()`). Needed because the challenge/domain transcripts
/// hash points in their COMPRESSED form, and the contract receives them uncompressed.
pub(crate) const HALF_P_BE: [u8; 48] = [
    0x0d, 0x00, 0x88, 0xf5, 0x1c, 0xbf, 0xf3, 0x4d, 0x25, 0x8d, 0xd3, 0xdb, 0x21, 0xa5, 0xd6, 0x6b,
    0xb2, 0x3b, 0xa5, 0xc2, 0x79, 0xc2, 0x89, 0x5f, 0xb3, 0x98, 0x69, 0x50, 0x7b, 0x58, 0x7b, 0x12,
    0x0f, 0x55, 0xff, 0xff, 0x58, 0xa9, 0xff, 0xff, 0xdc, 0xff, 0x7f, 0xff, 0xff, 0xff, 0xd5, 0x55,
];

const SCHEMA_MESSAGE_COUNT: u32 = 12;

fn sha256(env: &Env, data: &Bytes) -> [u8; 32] {
    env.crypto().sha256(data).to_array()
}

/// RFC 9380 §5.3.1 `expand_message_xmd` with SHA-256, specialised to `len_in_bytes = 48`
/// (`ell = 2`). Produces the 48-byte uniform string that `hash_to_scalar` reduces mod `r`. The
/// host offers no raw `expand_message_xmd`, so this is built from `env.crypto().sha256`.
fn expand_message_xmd_48(env: &Env, msg: &Bytes, dst: &[u8]) -> [u8; 48] {
    // DST_prime = DST || I2OSP(len(DST), 1)
    let mut dst_prime = Bytes::from_slice(env, dst);
    dst_prime.push_back(dst.len() as u8);

    // b_0 = H(Z_pad || msg || l_i_b_str || I2OSP(0,1) || DST_prime), Z_pad = 64 zero bytes,
    // l_i_b_str = I2OSP(48, 2) = 0x0030.
    let mut b0 = Bytes::from_array(env, &[0u8; 64]);
    b0.append(msg);
    b0.extend_from_array(&[0x00u8, 0x30u8]);
    b0.push_back(0u8);
    b0.append(&dst_prime);
    let b_0 = sha256(env, &b0);

    // b_1 = H(b_0 || I2OSP(1,1) || DST_prime)
    let mut b1 = Bytes::from_array(env, &b_0);
    b1.push_back(1u8);
    b1.append(&dst_prime);
    let b_1 = sha256(env, &b1);

    // b_2 = H((b_0 XOR b_1) || I2OSP(2,1) || DST_prime)
    let mut xor = [0u8; 32];
    for i in 0..32 {
        xor[i] = b_0[i] ^ b_1[i];
    }
    let mut b2 = Bytes::from_array(env, &xor);
    b2.push_back(2u8);
    b2.append(&dst_prime);
    let b_2 = sha256(env, &b2);

    // uniform_bytes = (b_1 || b_2)[0..48]
    let mut out = [0u8; 48];
    out[0..32].copy_from_slice(&b_1);
    out[32..48].copy_from_slice(&b_2[0..16]);
    out
}

/// `hash_to_scalar(msg, dst) = OS2IP(expand_message_xmd(msg, dst, 48)) mod r` (util.js). The
/// 384-bit reduction is the two-limb recombination described on `C256_MOD_R`.
fn hash_to_scalar(env: &Env, msg: &Bytes, dst: &[u8]) -> Bls12381Fr {
    let uniform = expand_message_xmd_48(env, msg, dst);
    // hi = uniform[0..16] (128 bits, < r), lo = uniform[16..48] (256 bits).
    let mut hi_padded = [0u8; 32];
    hi_padded[16..].copy_from_slice(&uniform[0..16]);
    let hi = Bls12381Fr::from_bytes(BytesN::from_array(env, &hi_padded));
    let mut lo = [0u8; 32];
    lo.copy_from_slice(&uniform[16..48]);
    let lo = Bls12381Fr::from_bytes(BytesN::from_array(env, &lo));
    let c256 = Bls12381Fr::from_bytes(BytesN::from_array(env, &C256_MOD_R));
    hi * c256 + lo
}

fn is_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|b| *b == 0)
}

fn gt_be(a: &[u8], b: &[u8]) -> bool {
    for i in 0..a.len() {
        match a[i].cmp(&b[i]) {
            core::cmp::Ordering::Greater => return true,
            core::cmp::Ordering::Less => return false,
            core::cmp::Ordering::Equal => {}
        }
    }
    false
}

/// Serialise an uncompressed G1 point to its COMPRESSED form (48 bytes) as `@noble/curves`
/// `toBytes()` does: `x` with the compression bit (0x80) set and the sort bit (0x20) set iff
/// `y > (p-1)/2`. Pure byte arithmetic — no host call, and no decompression is ever needed.
fn g1_compress(p: &Bls12381G1Affine) -> [u8; 48] {
    let bytes = p.to_array();
    let mut out = [0u8; 48];
    out.copy_from_slice(&bytes[0..48]); // x
    let sort = gt_be(&bytes[48..96], &HALF_P_BE);
    out[0] |= 0x80;
    if sort {
        out[0] |= 0x20;
    }
    out
}

/// Serialise an uncompressed G2 point to its COMPRESSED form (96 bytes): `x_c1 || x_c0` with the
/// compression bit set and the sort bit from the first non-zero y component. Matches the
/// `fp2.encode` + `sortBit([y.c1, y.c0])` path in `@noble/curves` bls12-381.js.
fn g2_compress(p: &Bls12381G2Affine) -> [u8; 96] {
    let bytes = p.to_array();
    let mut out = [0u8; 96];
    out[0..48].copy_from_slice(&bytes[0..48]); // x_c1
    out[48..96].copy_from_slice(&bytes[48..96]); // x_c0
    let y_c1 = &bytes[96..144];
    let y_c0 = &bytes[144..192];
    let sort = if is_zero(y_c1) {
        gt_be(y_c0, &HALF_P_BE)
    } else {
        gt_be(y_c1, &HALF_P_BE)
    };
    out[0] |= 0x80;
    if sort {
        out[0] |= 0x20;
    }
    out
}

/// `create_generators(count = L+1 = 13, api_id)` (util.js) for the frozen 12-message schema. The
/// generators are a FIXED derivation constant — the only party-chosen input anywhere in the proof
/// is the issuer's `W` (fetched from the trusted registry), and the challenge binds `W` through
/// `calculate_domain`. A prover cannot substitute its own generators because there is nowhere to
/// inject them: this function ignores every untrusted input and re-derives from the DST constants.
pub fn create_generators(env: &Env) -> Vec<Bls12381G1Affine> {
    let count = SCHEMA_MESSAGE_COUNT + 1;
    let mut generators = Vec::new(env);
    let generator_seed = Bytes::from_slice(env, GENERATOR_SEED);
    let mut v = expand_message_xmd_48(env, &generator_seed, SEED_DST);
    for i in 1..=count {
        // v = expand_message(v || I2OSP(i, 8), seed_dst, 48). The index is serialised as an
        // 8-byte big-endian integer (I2OSP(i, 8)), NOT the 4-byte u32 native width — that is a
        // bit-exact wire detail the frozen vector pins.
        let mut vmsg = Bytes::from_array(env, &v);
        vmsg.extend_from_array(&(i as u64).to_be_bytes());
        v = expand_message_xmd_48(env, &vmsg, SEED_DST);
        // generator_i = hash_to_curve_g1(v, generator_dst)
        let vbytes = Bytes::from_array(env, &v);
        let dst = Bytes::from_slice(env, GENERATOR_DST);
        generators.push_back(env.crypto().bls12_381().hash_to_g1(&vbytes, &dst));
    }
    generators
}

/// `messages_to_scalars(messages, api_id)` — each disclosed message (UTF-8 `name=value`) is hashed
/// to a scalar via `hash_to_scalar(msg, map_dst)`.
pub fn messages_to_scalars(env: &Env, messages: &Vec<Bytes>) -> Vec<Bls12381Fr> {
    let mut scalars = Vec::new(env);
    for msg in messages.iter() {
        scalars.push_back(hash_to_scalar(env, &msg, MAP_DST));
    }
    scalars
}

/// `calculate_domain(PK, generators, header, api_id)` (util.js):
///
///   dom_array = (L, Q_1, H_1, ..., H_L)
///   dom_octs  = serialize(dom_array) || api_id
///   dom_input = PK || dom_octs || I2OSP(len(header), 8) || header
///   domain    = hash_to_scalar(dom_input, hash_to_scalar_dst)
///
/// `PK` is the COMPRESSED G2 public key and every generator is serialised COMPRESSED, so this
/// recomputes the compressed forms from the uncompressed inputs the registry / proof carry.
pub fn calculate_domain(
    env: &Env,
    pk_uncompressed: &Bls12381G2Affine,
    generators: &Vec<Bls12381G1Affine>,
    header: &Bytes,
) -> Bls12381Fr {
    // serialize(dom_array): I2OSP(L, 8) || Q_1 || H_1 .. H_L  (each compressed)
    let mut dom_octs = Bytes::new(env);
    dom_octs.extend_from_array(&(SCHEMA_MESSAGE_COUNT as u64).to_be_bytes());
    for g in generators.iter() {
        dom_octs.extend_from_array(&g1_compress(&g));
    }
    // dom_octs || api_id  (util.js: if(api_id.length > 0) dom_octs = dom_octs || api_id)
    dom_octs.extend_from_slice(API_ID);

    // dom_input = PK_compressed || dom_octs || I2OSP(header.len, 8) || header
    let mut dom_input = Bytes::from_array(env, &g2_compress(pk_uncompressed));
    dom_input.append(&dom_octs);
    dom_input.extend_from_array(&(header.len() as u64).to_be_bytes());
    dom_input.append(header);

    hash_to_scalar(env, &dom_input, H2S_DST)
}

/// The core `ProofVerify` check, mirroring `CoreProofVerify` + `ProofVerifyInit` +
/// `ProofChallengeCalculate` in the reference. Returns `true` iff the recomputed Fiat-Shamir
/// challenge equals the proof's challenge AND the pairing `e(Abar, W)·e(Bbar, -P2) == 1_GT` holds.
///
/// The challenge transcript is `c_octs = serialize(R, i1, msg_i1, ..., Abar, Bbar, D, T1, T2,
/// domain) || I2OSP(len(ph), 8) || ph`, with every point COMPRESSED and every scalar 32 bytes —
/// which is why the points must be compressed here (there is no decompression host function and
/// the contract receives them uncompressed).
#[allow(clippy::too_many_arguments)]
pub fn verify_bbs_proof(
    env: &Env,
    pk_uncompressed: &Bls12381G2Affine,
    header: &Bytes,
    ph: &Bytes,
    disclosed_indexes: &Vec<u32>,
    disclosed_messages: &Vec<Bytes>,
    proof: &BbsProof,
) -> bool {
    if disclosed_indexes.len() != disclosed_messages.len() {
        return false;
    }

    let generators = create_generators(env);

    let abar = Bls12381G1Affine::from_bytes(proof.a_bar.clone());
    let bbar = Bls12381G1Affine::from_bytes(proof.b_bar.clone());
    let d = Bls12381G1Affine::from_bytes(proof.d.clone());
    let e_hat = Bls12381Fr::from_bytes(proof.e_hat.clone());
    let r1_hat = Bls12381Fr::from_bytes(proof.r1_hat.clone());
    let r3_hat = Bls12381Fr::from_bytes(proof.r3_hat.clone());
    let challenge = Bls12381Fr::from_bytes(proof.challenge.clone());
    let mut m_hat: Vec<Bls12381Fr> = Vec::new(env);
    for b in proof.m_hat.iter() {
        m_hat.push_back(Bls12381Fr::from_bytes(b.clone()));
    }

    let msg_scalars = messages_to_scalars(env, disclosed_messages);
    let domain = calculate_domain(env, pk_uncompressed, &generators, header);

    let p1 = Bls12381G1Affine::from_bytes(BytesN::from_array(env, &P1_UNCOMPRESSED));
    let q1 = generators.get(0).unwrap();

    // T1 = Bbar·c + Abar·ê + D·r1̂  (MSM size 3)
    let mut vp1 = Vec::new(env);
    vp1.push_back(bbar.clone());
    vp1.push_back(abar.clone());
    vp1.push_back(d.clone());
    let mut vs1 = Vec::new(env);
    vs1.push_back(challenge.clone());
    vs1.push_back(e_hat.clone());
    vs1.push_back(r1_hat.clone());
    let t1 = env.crypto().bls12_381().g1_msm(vp1, vs1);

    // Bv = P1 + Q_1·domain + Σ H_i·msg_i  (i ∈ disclosed)
    let mut vp_bv = Vec::new(env);
    vp_bv.push_back(p1.clone());
    vp_bv.push_back(q1.clone());
    let mut vs_bv = Vec::new(env);
    vs_bv.push_back(Bls12381Fr::from_u256(U256::from_u32(env, 1)));
    vs_bv.push_back(domain.clone());
    for i in 0..disclosed_indexes.len() {
        let idx = disclosed_indexes.get(i).unwrap();
        let g = generators.get(idx + 1).unwrap();
        vp_bv.push_back(g);
        vs_bv.push_back(msg_scalars.get(i).unwrap());
    }
    let bv = env.crypto().bls12_381().g1_msm(vp_bv, vs_bv);

    // T2 = Bv·c + D·r3̂ + Σ H_j·m̂_j  (j ∈ hidden). Hidden indexes are the schema indexes absent
    // from `disclosed_indexes`, in ascending order; `m_hat` is in that same ascending order.
    let mut vp_t2 = Vec::new(env);
    vp_t2.push_back(bv.clone());
    vp_t2.push_back(d.clone());
    let mut vs_t2 = Vec::new(env);
    vs_t2.push_back(challenge.clone());
    vs_t2.push_back(r3_hat.clone());
    let mut m_hat_pos: u32 = 0;
    for hidden_idx in 0..SCHEMA_MESSAGE_COUNT {
        let mut is_disclosed = false;
        for i in 0..disclosed_indexes.len() {
            if disclosed_indexes.get(i).unwrap() == hidden_idx {
                is_disclosed = true;
                break;
            }
        }
        if !is_disclosed {
            let g = generators.get(hidden_idx + 1).unwrap();
            vp_t2.push_back(g);
            vs_t2.push_back(m_hat.get(m_hat_pos).unwrap());
            m_hat_pos += 1;
        }
    }
    let t2 = env.crypto().bls12_381().g1_msm(vp_t2, vs_t2);

    // Recompute the challenge.
    let recomputed = proof_challenge(
        env,
        disclosed_indexes,
        &msg_scalars,
        &abar,
        &bbar,
        &d,
        &t1,
        &t2,
        &domain,
        ph,
    );

    if recomputed != challenge {
        return false;
    }

    // Pairing check: e(Abar, W) · e(Bbar, -BP2) == 1_GT.
    let bp2 = Bls12381G2Affine::from_bytes(BytesN::from_array(env, &P2_UNCOMPRESSED));
    let neg_bp2 = -bp2;
    let mut vp_pair = Vec::new(env);
    vp_pair.push_back(abar);
    vp_pair.push_back(bbar);
    let mut vs_pair = Vec::new(env);
    vs_pair.push_back(pk_uncompressed.clone());
    vs_pair.push_back(neg_bp2);
    env.crypto().bls12_381().pairing_check(vp_pair, vs_pair)
}

/// `ProofChallengeCalculate` (proof.js): hash the transcript to a scalar and return it for the
/// equality check against the proof's `challenge` field.
#[allow(clippy::too_many_arguments)]
fn proof_challenge(
    env: &Env,
    disclosed_indexes: &Vec<u32>,
    msg_scalars: &Vec<Bls12381Fr>,
    abar: &Bls12381G1Affine,
    bbar: &Bls12381G1Affine,
    d: &Bls12381G1Affine,
    t1: &Bls12381G1Affine,
    t2: &Bls12381G1Affine,
    domain: &Bls12381Fr,
    ph: &Bytes,
) -> Bls12381Fr {
    // c_arr = (R, i1, msg_i1, ..., iR, msg_iR, Abar, Bbar, D, T1, T2, domain).
    // Numbers (R and indexes) serialise as I2OSP(·, 8); scalars as 32 bytes; points compressed.
    let mut c_octs = Bytes::new(env);
    c_octs.extend_from_array(&(disclosed_indexes.len() as u64).to_be_bytes());
    for i in 0..disclosed_indexes.len() {
        c_octs.extend_from_array(&(disclosed_indexes.get(i).unwrap() as u64).to_be_bytes());
        c_octs.extend_from_array(&msg_scalars.get(i).unwrap().to_bytes().to_array());
    }
    c_octs.extend_from_array(&g1_compress(abar));
    c_octs.extend_from_array(&g1_compress(bbar));
    c_octs.extend_from_array(&g1_compress(d));
    c_octs.extend_from_array(&g1_compress(t1));
    c_octs.extend_from_array(&g1_compress(t2));
    c_octs.extend_from_array(&domain.to_bytes().to_array());

    // c_octs || I2OSP(len(ph), 8) || ph
    c_octs.extend_from_array(&(ph.len() as u64).to_be_bytes());
    c_octs.append(ph);

    hash_to_scalar(env, &c_octs, H2S_DST)
}
