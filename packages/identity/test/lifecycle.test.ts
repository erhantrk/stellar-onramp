/**
 * Credential LIFETIME and SUBJECT binding.
 *
 * These are the two questions a BBS+ proof does not answer on its own. `over18=true` verified
 * against the issuer key says "some credential this issuer signed asserts over18" — it is silent
 * about *when* that credential was signed and about *whose* it is. Both gaps are exploitable in
 * exactly the same way: derive an honest, cryptographically perfect proof from a credential that
 * should no longer count.
 *
 * Everything here therefore checks a POLICY rejection over a VALID proof. If any of these ever
 * starts returning `valid: true`, the crypto is still fine and the product is still broken.
 */

import { describe, expect, it } from 'vitest';

import {
  CLAIM_INDEX,
  SCHEMA_VERSION,
  UNSAFE_NO_CHECKS,
  checkPredicate,
  computeSubjectBinding,
  credentialAudit,
  derive,
  gateOnrampPredicate,
  generateIssuerKeyPair,
  issue,
  issuerIdFromPublicKey,
  prove,
  standardOnrampPredicate,
  undisclosedCountFromProofBytes,
  verifyDetailed,
  type ProofBinding,
} from '../src/index.js';
import VECTORS from '../fixtures/vectors.json' with { type: 'json' };
import { BASE_BINDING, ISSUER_SEED, claimsFor } from './helpers.js';


const HOLDER_SALT = Uint8Array.from({ length: 32 }, (_, i) => 0x11 + i);
const OTHER_WALLET = 'CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC';

/** 2019-01-01 → 2020-01-01. Long dead. */
const DEAD = { issuedAt: 1_546_300_800, expiresAt: 1_577_836_800 };
const NOW = 1_767_225_600; // 2026-01-01

async function subjectBoundCredential(overrides = {}) {
  const kp = await generateIssuerKeyPair(ISSUER_SEED);
  const cred = await issue(
    claimsFor(kp.publicKey, {
      subjectBinding: computeSubjectBinding(BASE_BINDING.walletAddress, HOLDER_SALT),
      ...overrides,
    }),
    kp.secretKey,
  );
  return { kp, cred };
}

describe('credential expiry', () => {
  it('rejects a proof from a credential that expired years ago', async () => {
    const { kp, cred } = await subjectBoundCredential(DEAD);
    const proof = await prove(cred, gateOnrampPredicate(), BASE_BINDING);
    const r = await checkPredicate(proof, gateOnrampPredicate(), kp.publicKey, BASE_BINDING, {
      ...UNSAFE_NO_CHECKS,
      currentTime: NOW,
    });
    expect(r.valid).toBe(false);
    expect(r.reason).toBe('credential-expired');
  });

  it('accepts the same credential while it is still live', async () => {
    const { kp, cred } = await subjectBoundCredential(DEAD);
    const r = await checkPredicate(
      await prove(cred, gateOnrampPredicate(), BASE_BINDING),
      gateOnrampPredicate(),
      kp.publicKey,
      BASE_BINDING,
      { ...UNSAFE_NO_CHECKS, currentTime: DEAD.expiresAt - 1 },
    );
    expect(r.valid).toBe(true);
  });

  it('treats expiresAt as inclusive and the next second as dead', async () => {
    const { kp, cred } = await subjectBoundCredential(DEAD);
    const proof = await prove(cred, gateOnrampPredicate(), BASE_BINDING);
    const at = await checkPredicate(proof, gateOnrampPredicate(), kp.publicKey, BASE_BINDING, {
      ...UNSAFE_NO_CHECKS,
      currentTime: DEAD.expiresAt,
    });
    expect(at.valid).toBe(true);
    const after = await checkPredicate(proof, gateOnrampPredicate(), kp.publicKey, BASE_BINDING, {
      ...UNSAFE_NO_CHECKS,
      currentTime: DEAD.expiresAt + 1,
    });
    expect(after.reason).toBe('credential-expired');
  });

  it('FAILS CLOSED when expiry is demanded but index 4 is hidden', async () => {
    // The dangerous shape: relying party asks for expiry enforcement over a predicate that does
    // not disclose expiresAt. Skipping the check silently would report `valid` on an unchecked
    // credential, which is strictly worse than not offering the option at all.
    const { kp, cred } = await subjectBoundCredential(DEAD);
    const proof = await prove(cred, standardOnrampPredicate(), BASE_BINDING);
    const r = await checkPredicate(
      proof,
      standardOnrampPredicate(),
      kp.publicKey,
      BASE_BINDING,
      { ...UNSAFE_NO_CHECKS, currentTime: NOW },
    );
    expect(r.valid).toBe(false);
    expect(r.reason).toBe('disclosure-shape');
    expect(r.detail).toContain('expiresAt');
  });

  it('rejects a credential whose issuedAt is beyond the clock-skew window', async () => {
    const { kp, cred } = await subjectBoundCredential({
      issuedAt: NOW + 86_400,
      expiresAt: NOW + 172_800,
    });
    // it to the whole metadata block; `derive` refuses a duplicate index, so do not re-add it.
    const disclose = credentialAudit().disclose;
    expect(disclose).toContain(CLAIM_INDEX.issuedAt);
    const proof = await derive(cred, disclose, BASE_BINDING);
    const r = await verifyDetailed(proof, kp.publicKey, BASE_BINDING, {
      ...UNSAFE_NO_CHECKS,
      currentTime: NOW,
    });
    expect(r.valid).toBe(false);
    expect(r.reason).toBe('credential-expired');
    expect(r.detail).toContain('future');
  });

  it('presentation ledgerExpiry does not stand in for credential expiry', async () => {
    // The exact confusion this whole file exists for: ledgerExpiry is chosen by the RELYING
    // PARTY at challenge time, so the holder of a dead credential can always get a fresh,
    // far-future one. A ledger check that passes must not imply the credential is live.
    const { kp, cred } = await subjectBoundCredential(DEAD);
    const generous: ProofBinding = { ...BASE_BINDING, ledgerExpiry: 4_000_000_000 };
    const proof = await prove(cred, gateOnrampPredicate(), generous);
    const ledgerOnly = await checkPredicate(proof, gateOnrampPredicate(), kp.publicKey, generous, {
      ...UNSAFE_NO_CHECKS,
      currentLedger: 1_000_000,
    });
    expect(ledgerOnly.valid).toBe(true); // ledger bound is genuinely satisfied...
    const both = await checkPredicate(proof, gateOnrampPredicate(), kp.publicKey, generous, {
      ...UNSAFE_NO_CHECKS,
      currentLedger: 1_000_000,
      currentTime: NOW,
    });
    expect(both.reason).toBe('credential-expired'); // ...and the credential is still dead.
  });
});

describe('subject binding', () => {
  it("rejects Alice's credential presented for Bob's wallet", async () => {
    const { kp, cred } = await subjectBoundCredential();
    const bobBinding: ProofBinding = { ...BASE_BINDING, walletAddress: OTHER_WALLET };
    const proof = await prove(cred, gateOnrampPredicate(), bobBinding);
    const r = await checkPredicate(proof, gateOnrampPredicate(), kp.publicKey, bobBinding, {
      ...UNSAFE_NO_CHECKS,
      expectedSubjectBinding: computeSubjectBinding(OTHER_WALLET, HOLDER_SALT),
    });
    expect(r.valid).toBe(false);
    expect(r.reason).toBe('subject-mismatch');
  });

  it('accepts the credential for the wallet it was issued to', async () => {
    const { kp, cred } = await subjectBoundCredential();
    const proof = await prove(cred, gateOnrampPredicate(), BASE_BINDING);
    const r = await checkPredicate(proof, gateOnrampPredicate(), kp.publicKey, BASE_BINDING, {
      ...UNSAFE_NO_CHECKS,
      expectedSubjectBinding: computeSubjectBinding(BASE_BINDING.walletAddress, HOLDER_SALT),
    });
    expect(r.valid).toBe(true);
  });

  it('FAILS CLOSED when subject binding is demanded but index 5 is hidden', async () => {
    const { kp, cred } = await subjectBoundCredential();
    const proof = await prove(cred, standardOnrampPredicate(), BASE_BINDING);
    const r = await checkPredicate(proof, standardOnrampPredicate(), kp.publicKey, BASE_BINDING, {
      ...UNSAFE_NO_CHECKS,
      expectedSubjectBinding: computeSubjectBinding(BASE_BINDING.walletAddress, HOLDER_SALT),
    });
    expect(r.valid).toBe(false);
    expect(r.reason).toBe('disclosure-shape');
    expect(r.detail).toContain('subjectBinding');
  });

  it('is wallet-specific and salt-specific', async () => {
    const a = computeSubjectBinding(BASE_BINDING.walletAddress, HOLDER_SALT);
    expect(computeSubjectBinding(OTHER_WALLET, HOLDER_SALT)).not.toBe(a);
    expect(computeSubjectBinding(BASE_BINDING.walletAddress, new Uint8Array(32))).not.toBe(a);
    expect(a).toMatch(/^[0-9a-f]{64}$/);
  });

  it('refuses a malformed wallet address or salt', () => {
    expect(() => computeSubjectBinding('not-an-address', HOLDER_SALT)).toThrow();
    expect(() => computeSubjectBinding(BASE_BINDING.walletAddress, new Uint8Array(31))).toThrow();
  });
});

describe('gateOnrampPredicate', () => {
  // WIRE CONTRACT. This disclosure set is shared with fixtures/vectors.json (case "gate-onramp")
  // and with the not-yet-written on-chain Rust verifier. Do not change these numbers without
  // changing the fixture in the same commit.
  it('discloses [0,1,2,3,4,5,6,8]', () => {
    expect(gateOnrampPredicate().disclose).toEqual([
      CLAIM_INDEX.schemaVersion,
      CLAIM_INDEX.issuerId,
      CLAIM_INDEX.revocationIndex,
      CLAIM_INDEX.issuedAt,
      CLAIM_INDEX.expiresAt,
      CLAIM_INDEX.subjectBinding,
      CLAIM_INDEX.over18,
      CLAIM_INDEX.notSanctioned,
    ]);
    expect(gateOnrampPredicate().disclose).toEqual([0, 1, 2, 3, 4, 5, 6, 8]);
    expect(gateOnrampPredicate().expect).toEqual({
      schemaVersion: SCHEMA_VERSION,
      over18: true,
      notSanctioned: true,
    });
  });

  it('yields R=8 / U=4 / a 400-byte proof and surfaces the revocation index', async () => {
    const { kp, cred } = await subjectBoundCredential();
    const p = gateOnrampPredicate();
    const proof = await prove(cred, p, BASE_BINDING);
    expect(p.disclose.length).toBe(8);
    expect(proof.disclosedIndexes.length).toBe(8);
    expect(undisclosedCountFromProofBytes(proof.proof.length)).toBe(4);
    expect(proof.proof.length).toBe(144 + 32 * (4 + 4));
    expect(proof.proof.length).toBe(400);
    const r = await checkPredicate(proof, p, kp.publicKey, BASE_BINDING, {
      ...UNSAFE_NO_CHECKS,
      currentTime: NOW,
      expectedSubjectBinding: computeSubjectBinding(BASE_BINDING.walletAddress, HOLDER_SALT),
    });
    expect(r.valid).toBe(true);
    expect(r.claims?.revocationIndex).toBe(cred.claims.revocationIndex);
    // The two checks that were unreachable before the widening.
    expect(r.claims?.schemaVersion).toBe(SCHEMA_VERSION);
    expect(r.claims?.issuerId).toBe(issuerIdFromPublicKey(kp.publicKey));
  });

  it('the vectors.json "gate-onramp" case pins the same wire contract', () => {
    type VectorCase = {
      name: string;
      disclosedIndexes: number[];
      undisclosedCount: number;
      proof: { length: number };
    };
    const c = (VECTORS.cases as VectorCase[]).find((x) => x.name === 'gate-onramp');
    expect(c).toBeDefined();
    expect(c?.disclosedIndexes).toEqual([...gateOnrampPredicate().disclose]);
    expect(c?.undisclosedCount).toBe(4);
    expect(c?.proof.length).toBe(400);
  });

  it('still rejects a fabricated expiry, because the value is only read after ProofVerify', async () => {
    const { kp, cred } = await subjectBoundCredential(DEAD);
    const proof = await prove(cred, gateOnrampPredicate(), BASE_BINDING);
    const forged = {
      ...proof,
      disclosedMessages: proof.disclosedMessages.map((m) =>
        m.startsWith('expiresAt=') ? `expiresAt=${NOW + 86_400}` : m,
      ),
    };
    const r = await checkPredicate(forged, gateOnrampPredicate(), kp.publicKey, BASE_BINDING, {
      ...UNSAFE_NO_CHECKS,
      currentTime: NOW,
    });
    expect(r.valid).toBe(false);
    expect(r.reason).toBe('bbs-invalid');
  });
});
