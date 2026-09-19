import { describe, expect, it } from 'vitest';

import {
  CLAIM_INDEX,
  FP_BYTES,
  G1_COMPRESSED_BYTES,
  G1_UNCOMPRESSED_BYTES,
  G2_COMPRESSED_BYTES,
  G2_UNCOMPRESSED_BYTES,
  MAX_SCHEMA_ATTRIBUTES,
  PointError,
  compressG1,
  compressG2,
  decompressG1,
  decompressG2,
  derive,
  expectedProofBytes,
  flattenSorobanProof,
  splitProof,
  splitSignature,
  undisclosedCountFromProofBytes,
} from '../src/index.js';
import { BASE_BINDING, fixture, flipBit } from './helpers.js';


describe('point decompression for Soroban', () => {
  it('expands the issuer G2 key 96 -> 192 and round-trips', async () => {
    const { issuer } = await fixture();
    expect(issuer.publicKey.length).toBe(G2_COMPRESSED_BYTES);
    const un = decompressG2(issuer.publicKey);
    expect(un.length).toBe(G2_UNCOMPRESSED_BYTES);
    expect(compressG2(un)).toEqual(issuer.publicKey);
  });

  it('expands the signature G1 point 48 -> 96 and round-trips', async () => {
    const { credential } = await fixture();
    const { a, e } = splitSignature(credential.signature);
    expect(a.length).toBe(G1_UNCOMPRESSED_BYTES);
    expect(e.length).toBe(32);
    expect(compressG1(a)).toEqual(credential.signature.subarray(0, G1_COMPRESSED_BYTES));
  });

  it('strips the compression flag — the Soroban host rejects it', async () => {
    const { issuer, credential } = await fixture();
    // Compressed BLS points always set the MSB of byte 0; uncompressed must not.
    expect(issuer.publicKey[0]! & 0x80).toBe(0x80);
    expect(decompressG2(issuer.publicKey)[0]! & 0xe0).toBe(0);
    expect(credential.signature[0]! & 0x80).toBe(0x80);
    expect(splitSignature(credential.signature).a[0]! & 0xe0).toBe(0);
  });

  it('lays out G1 as be(X) || be(Y) and G2 as be(X_c1)||be(X_c0)||be(Y_c1)||be(Y_c0)', async () => {
    const { issuer, credential } = await fixture();
    const g1 = splitSignature(credential.signature).a;
    expect(g1.length).toBe(2 * FP_BYTES);
    const g2 = decompressG2(issuer.publicKey);
    expect(g2.length).toBe(4 * FP_BYTES);

    // Every 48-byte limb must be a valid Fp element (< p), i.e. its top 3 bits are clear
    // because p < 2^381.
    for (let i = 0; i < g2.length; i += FP_BYTES) {
      expect(g2[i]! & 0xe0).toBe(0);
    }
    // Recompressing a limb-reordered G2 must not silently succeed as the same key.
    const reordered = new Uint8Array(g2);
    reordered.set(g2.subarray(FP_BYTES, 2 * FP_BYTES), 0);
    reordered.set(g2.subarray(0, FP_BYTES), FP_BYTES);
    let sameKey = false;
    try {
      sameKey = compressG2(reordered).every((b, i) => b === issuer.publicKey[i]);
    } catch {
      sameKey = false;
    }
    expect(sameKey).toBe(false);
  });

  it('rejects wrong-length and off-curve inputs', () => {
    expect(() => decompressG1(new Uint8Array(47))).toThrow(PointError);
    expect(() => decompressG2(new Uint8Array(97))).toThrow(PointError);
    expect(() => compressG1(new Uint8Array(95))).toThrow(PointError);
    expect(() => compressG2(new Uint8Array(191))).toThrow(PointError);
    expect(() => compressG1(new Uint8Array(G1_UNCOMPRESSED_BYTES).fill(1))).toThrow();
  });
});

describe('proof decomposition', () => {
  it('splits into 3 G1 points and 4+U scalars, challenge last', async () => {
    const { credential } = await fixture();
    const proof = await derive(credential, [CLAIM_INDEX.over18, CLAIM_INDEX.notSanctioned], BASE_BINDING);
    const sp = splitProof(proof.proof);

    expect(sp.undisclosedCount).toBe(10);
    for (const p of [sp.abar, sp.bbar, sp.d]) expect(p.length).toBe(G1_UNCOMPRESSED_BYTES);
    for (const s of [sp.eHat, sp.r1Hat, sp.r3Hat, sp.challenge]) expect(s.length).toBe(32);
    expect(sp.mHat).toHaveLength(10);

    // The challenge is the LAST 32 bytes of the wire proof, after the mHat block.
    expect(sp.challenge).toEqual(proof.proof.slice(-32));
    // ...and mHat_0 sits immediately after the three "fixed" scalars.
    expect(sp.mHat[0]).toEqual(proof.proof.slice(144 + 96, 144 + 128));
  });

  it('produces a flat Soroban blob of 288 + 32*(4+U) bytes', async () => {
    const { credential } = await fixture();
    for (const r of [0, 1, 2, 5, 12]) {
      const proof = await derive(credential, [...Array(r).keys()], BASE_BINDING);
      const u = 12 - r;
      const flat = flattenSorobanProof(splitProof(proof.proof));
      expect(flat.length).toBe(288 + 32 * (4 + u));
      // Exactly 144 bytes larger than the compressed proof: 3 points × (96 − 48).
      expect(flat.length - proof.proof.length).toBe(144);
    }
  });

  it('infers U from the byte length and rejects impossible lengths', () => {
    expect(undisclosedCountFromProofBytes(272)).toBe(0);
    expect(undisclosedCountFromProofBytes(592)).toBe(10);
    expect(undisclosedCountFromProofBytes(expectedProofBytes(7))).toBe(7);
    expect(() => undisclosedCountFromProofBytes(271)).toThrow(PointError);
    expect(() => undisclosedCountFromProofBytes(273)).toThrow(PointError);
    expect(() => undisclosedCountFromProofBytes(0)).toThrow(PointError);
  });

  /**
   * `MAX_SCHEMA_ATTRIBUTES = 39` was a constant that only a test compared `12` against; a
   * length-derived U was unbounded, so a 32 KB byte string decoded to U = 1,014 and `splitProof`
   * allocated 1,014 scalars off it. Unreachable at N = 12 — the point is the v2 append.
   */
  it('refuses a U past MAX_SCHEMA_ATTRIBUTES, from either direction', () => {
    // The boundary itself is legal, in both directions, and round-trips.
    const atCap = expectedProofBytes(MAX_SCHEMA_ATTRIBUTES);
    expect(atCap).toBe(144 + 32 * (4 + 39));
    expect(undisclosedCountFromProofBytes(atCap)).toBe(MAX_SCHEMA_ATTRIBUTES);

    // One past is not.
    expect(() => expectedProofBytes(MAX_SCHEMA_ATTRIBUTES + 1)).toThrow(PointError);
    expect(() => undisclosedCountFromProofBytes(atCap + 32)).toThrow(
      /exceeds MAX_SCHEMA_ATTRIBUTES 39/,
    );
    // A length that is well-formed under the size law but absurd: U = 1,014.
    const huge = 272 + 32 * 1_014;
    expect(() => undisclosedCountFromProofBytes(huge)).toThrow(PointError);
    expect(() => splitProof(new Uint8Array(huge))).toThrow(PointError);
  });

  it('refuses to decompose a proof whose points are corrupted', async () => {
    const { credential } = await fixture();
    const proof = await derive(credential, [CLAIM_INDEX.over18], BASE_BINDING);
    // Clearing the compression flag makes byte 0 an invalid compressed encoding.
    const bad = flipBit(proof.proof, 0, 7);
    expect(() => splitProof(bad)).toThrow();
  });
});
