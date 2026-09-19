import { describe, expect, it } from 'vitest';

import {
  UNSAFE_NO_CHECKS,
  CLAIM_INDEX,
  CredentialError,
  SCHEMA_ATTRIBUTE_COUNT,
  SIGNATURE_BYTES,
  derive,
  deserializeCredential,
  deserializeProof,
  disclosedClaimNames,
  expectedProofBytes,
  generateIssuerKeyPair,
  issue,
  issuerIdFromPublicKey,
  issuerPublicKey,
  serializeCredential,
  serializeProof,
  verify,
  verifyCredential,
  verifyDetailed,
} from '../src/index.js';
import { BASE_BINDING, ISSUER_SEED, claimsFor, fixture } from './helpers.js';


describe('issuance', () => {
  it('produces an 80-byte signature over a 96-byte compressed G2 key', async () => {
    const { credential, issuer } = await fixture();
    expect(credential.signature.length).toBe(SIGNATURE_BYTES);
    expect(issuer.publicKey.length).toBe(96);
    expect(issuer.secretKey.length).toBe(32);
    expect(credential.messages.length).toBe(SCHEMA_ATTRIBUTE_COUNT);
    expect(await verifyCredential(credential)).toBe(true);
  });

  it('is deterministic for a fixed seed', async () => {
    const a = await generateIssuerKeyPair(ISSUER_SEED);
    const b = await generateIssuerKeyPair(ISSUER_SEED);
    expect(a.secretKey).toEqual(b.secretKey);
    expect(a.publicKey).toEqual(b.publicKey);

    const c1 = await issue(claimsFor(a.publicKey), a.secretKey);
    const c2 = await issue(claimsFor(b.publicKey), b.secretKey);
    expect(c1.signature).toEqual(c2.signature);
  });

  it('derives the public key from the secret key consistently', async () => {
    const kp = await generateIssuerKeyPair(ISSUER_SEED);
    expect(await issuerPublicKey(kp.secretKey)).toEqual(kp.publicKey);
  });

  it('rejects a claim set signed with a key that does not match issuerId', async () => {
    const kp = await generateIssuerKeyPair(ISSUER_SEED);
    const other = await generateIssuerKeyPair(new Uint8Array(32).fill(9));
    await expect(issue(claimsFor(other.publicKey), kp.secretKey)).rejects.toThrow(CredentialError);
  });

  it('rejects expiry <= issuance', async () => {
    const kp = await generateIssuerKeyPair(ISSUER_SEED);
    await expect(
      issue(claimsFor(kp.publicKey, { expiresAt: 1767225600 }), kp.secretKey),
    ).rejects.toThrow(CredentialError);
  });

  it('rejects a malformed secret key', async () => {
    const kp = await generateIssuerKeyPair(ISSUER_SEED);
    await expect(issue(claimsFor(kp.publicKey), new Uint8Array(31))).rejects.toThrow(
      CredentialError,
    );
  });

  it('rejects a wrong schema version', async () => {
    const kp = await generateIssuerKeyPair(ISSUER_SEED);
    await expect(
      issue(claimsFor(kp.publicKey, { schemaVersion: '2' }), kp.secretKey),
    ).rejects.toThrow(CredentialError);
  });

  it('detects a tampered credential message', async () => {
    const { credential } = await fixture();
    const tampered = {
      ...credential,
      messages: credential.messages.map((m, i) => (i === CLAIM_INDEX.over18 ? 'over18=false' : m)),
    };
    expect(await verifyCredential(tampered)).toBe(false);
  });

  it('binds issuerId to the compressed public key', async () => {
    const { issuer, credential } = await fixture();
    expect(credential.claims.issuerId).toBe(issuerIdFromPublicKey(issuer.publicKey));
    expect(credential.claims.issuerId).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe('derive / verify happy paths', () => {
  it('verifies a standard two-attribute disclosure', async () => {
    const { credential, issuer } = await fixture();
    const proof = await derive(credential, [CLAIM_INDEX.over18, CLAIM_INDEX.notSanctioned], BASE_BINDING);
    expect(await verify(proof, issuer.publicKey, BASE_BINDING, UNSAFE_NO_CHECKS)).toBe(true);
    expect(disclosedClaimNames(proof)).toEqual(['over18', 'notSanctioned']);
  });

  it('verifies the empty disclosure set (possession only)', async () => {
    const { credential, issuer } = await fixture();
    const proof = await derive(credential, [], BASE_BINDING);
    expect(proof.disclosedIndexes).toEqual([]);
    expect(proof.proof.length).toBe(expectedProofBytes(SCHEMA_ATTRIBUTE_COUNT));
    const r = await verifyDetailed(proof, issuer.publicKey, BASE_BINDING, UNSAFE_NO_CHECKS);
    expect(r.valid).toBe(true);
    expect(r.claims).toEqual({});
  });

  it('verifies the full disclosure set', async () => {
    const { credential, issuer } = await fixture();
    const all = [...Array(SCHEMA_ATTRIBUTE_COUNT).keys()];
    const proof = await derive(credential, all, BASE_BINDING);
    expect(proof.proof.length).toBe(expectedProofBytes(0));
    expect(proof.proof.length).toBe(272);
    const r = await verifyDetailed(proof, issuer.publicKey, BASE_BINDING, UNSAFE_NO_CHECKS);
    expect(r.valid).toBe(true);
    expect(r.claims?.over18).toBe(true);
    expect(r.claims?.subjectBinding).toBe(credential.claims.subjectBinding);
  });

  it('accepts unsorted revealedIndices and normalizes them', async () => {
    const { credential, issuer } = await fixture();
    const proof = await derive(credential, [CLAIM_INDEX.notSanctioned, CLAIM_INDEX.over18], BASE_BINDING);
    expect(proof.disclosedIndexes).toEqual([CLAIM_INDEX.over18, CLAIM_INDEX.notSanctioned]);
    expect(await verify(proof, issuer.publicKey, BASE_BINDING, UNSAFE_NO_CHECKS)).toBe(true);
  });

  it('is unlinkable: two derivations of the same disclosure differ', async () => {
    const { credential, issuer } = await fixture();
    const a = await derive(credential, [CLAIM_INDEX.over18], BASE_BINDING);
    const b = await derive(credential, [CLAIM_INDEX.over18], BASE_BINDING);
    expect(a.proof).not.toEqual(b.proof);
    expect(await verify(a, issuer.publicKey, BASE_BINDING, UNSAFE_NO_CHECKS)).toBe(true);
    expect(await verify(b, issuer.publicKey, BASE_BINDING, UNSAFE_NO_CHECKS)).toBe(true);
  });

  it('checks expected disclosed claim values', async () => {
    const { credential, issuer } = await fixture();
    const proof = await derive(credential, [CLAIM_INDEX.over18], BASE_BINDING);
    expect(await verify(proof, issuer.publicKey, BASE_BINDING, {
      ...UNSAFE_NO_CHECKS,
      expectedClaims: { over18: true },
    })).toBe(true);
    expect(await verify(proof, issuer.publicKey, BASE_BINDING, {
      ...UNSAFE_NO_CHECKS,
      expectedClaims: { over18: false },
    })).toBe(false);
    // Asking about a claim that was not disclosed must fail, not silently pass.
    expect(await verify(proof, issuer.publicKey, BASE_BINDING, {
      ...UNSAFE_NO_CHECKS,
      expectedClaims: { over21: true },
    })).toBe(false);
  });

  it('reports a false boolean claim as a claim mismatch, not a crypto failure', async () => {
    const kp = await generateIssuerKeyPair(ISSUER_SEED);
    const minor = await issue(claimsFor(kp.publicKey, { over18: false }), kp.secretKey);
    const proof = await derive(minor, [CLAIM_INDEX.over18], BASE_BINDING);
    const r = await verifyDetailed(proof, kp.publicKey, BASE_BINDING, {
      ...UNSAFE_NO_CHECKS,
      expectedClaims: { over18: true },
    });
    expect(r.valid).toBe(false);
    expect(r.reason).toBe('claim-mismatch');
  });

  it('survives JSON serialization round-trips', async () => {
    const { credential, issuer } = await fixture();
    const proof = await derive(credential, [CLAIM_INDEX.over18], BASE_BINDING);

    const cred2 = deserializeCredential(JSON.parse(JSON.stringify(serializeCredential(credential))));
    expect(await verifyCredential(cred2)).toBe(true);

    const proof2 = deserializeProof(JSON.parse(JSON.stringify(serializeProof(proof))));
    expect(await verify(proof2, issuer.publicKey, BASE_BINDING, UNSAFE_NO_CHECKS)).toBe(true);
  });
});

/**
 * revealing MORE than the relying party asked for was accepted. `checkPredicate` was the only door
 * that closed it; `verifyDetailed` and `verify` are exported too and had no way to express the ask.
 *
 * It is a HOLDER-privacy failure, not a relying-party security failure — a proof CLAIMING an index
 * it did not reveal is still caught by the U-versus-byte cross-check — which is exactly why the
 * relying party is the only party who can refuse it, and why silence was the wrong default.
 */
describe('the disclosure set is pinned, not just the values', () => {
  const gate = [CLAIM_INDEX.over18, CLAIM_INDEX.notSanctioned];

  it('accepts a proof that discloses EXACTLY the asked-for set', async () => {
    const { credential, issuer } = await fixture();
    const proof = await derive(credential, gate, BASE_BINDING);
    const r = await verifyDetailed(proof, issuer.publicKey, BASE_BINDING, {
      ...UNSAFE_NO_CHECKS,
      expectedDisclosedIndexes: gate,
    });
    expect(r.reason).toBeUndefined();
    expect(r.valid).toBe(true);
  });

  it('REJECTS a proof that discloses MORE than was asked for', async () => {
    const { credential, issuer } = await fixture();
    // Cryptographically perfect, every asked-for value correct — and it hands over `issuedAt`,
    // `revocationIndex` and `subjectBinding` on top. `subjectBinding` is a stable per-credential
    // correlation handle; a relying party that did not ask for it should not be storing it.
    const over = await derive(
      credential,
      [...gate, CLAIM_INDEX.issuedAt, CLAIM_INDEX.revocationIndex, CLAIM_INDEX.subjectBinding],
      BASE_BINDING,
    );
    expect(await verify(over, issuer.publicKey, BASE_BINDING, UNSAFE_NO_CHECKS)).toBe(true);

    const r = await verifyDetailed(over, issuer.publicKey, BASE_BINDING, {
      ...UNSAFE_NO_CHECKS,
      expectedClaims: { over18: true, notSanctioned: true },
      expectedDisclosedIndexes: gate,
    });
    expect(r.valid).toBe(false);
    expect(r.reason).toBe('disclosure-shape');
    expect(r.detail).toMatch(/expectedDisclosedIndexes \[6,8\] does not match/);
  });

  it('REJECTS a proof that discloses LESS, and order does not matter', async () => {
    const { credential, issuer } = await fixture();
    const narrow = await derive(credential, [CLAIM_INDEX.over18], BASE_BINDING);
    const r = await verifyDetailed(narrow, issuer.publicKey, BASE_BINDING, {
      ...UNSAFE_NO_CHECKS,
      expectedDisclosedIndexes: [CLAIM_INDEX.notSanctioned, CLAIM_INDEX.over18], // unsorted ask
    });
    expect(r.valid).toBe(false);
    expect(r.reason).toBe('disclosure-shape');

    // ...and the same unsorted ask against the matching proof PASSES, so the sort is normalising
    // and not accidentally rejecting every caller who did not pre-sort.
    const both = await derive(credential, gate, BASE_BINDING);
    const ok = await verifyDetailed(both, issuer.publicKey, BASE_BINDING, {
      ...UNSAFE_NO_CHECKS,
      expectedDisclosedIndexes: [CLAIM_INDEX.notSanctioned, CLAIM_INDEX.over18],
    });
    expect(ok.valid).toBe(true);
  });

  it('[] means "reveal nothing" and is NOT a synonym for UNSAFE_SKIP', async () => {
    const { credential, issuer } = await fixture();
    const empty = await derive(credential, [], BASE_BINDING);
    const some = await derive(credential, [CLAIM_INDEX.over18], BASE_BINDING);

    const emptyOk = await verifyDetailed(empty, issuer.publicKey, BASE_BINDING, {
      ...UNSAFE_NO_CHECKS,
      expectedDisclosedIndexes: [],
    });
    expect(emptyOk.valid).toBe(true);

    const someVsEmpty = await verifyDetailed(some, issuer.publicKey, BASE_BINDING, {
      ...UNSAFE_NO_CHECKS,
      expectedDisclosedIndexes: [],
    });
    expect(someVsEmpty.valid).toBe(false);
    expect(someVsEmpty.reason).toBe('disclosure-shape');
  });

  it('a plain-JS caller with a garbage ask is REJECTED, never read as "skip"', async () => {
    const { credential, issuer } = await fixture();
    const proof = await derive(credential, gate, BASE_BINDING);
    // Every one of these used to be impossible to express at all; none of them may now be read
    // as "any disclosure set is fine". Same fail-closed shape as expectedClaims' N1 guard.
    for (const bad of [
      undefined,
      null,
      'over18',
      6,
      new Set([6, 8]),
      [6, 1.5],
      [6, -1],
      [6, 12],
      // A SPARSE array. `Array.prototype.some` skips holes, so a validator built on `.some`
      // waved `[6, , 8]` through and it landed in `disclosure-shape` via the set comparison
      // bucket is the whole point of this test.
      [6, , 8],
      [, 6, 8],
      new Array(2),
      // Boxed Numbers are objects, not integers.
      [new Number(6), new Number(8)],
    ]) {
      const r = await verifyDetailed(proof, issuer.publicKey, BASE_BINDING, {
        ...UNSAFE_NO_CHECKS,
        expectedDisclosedIndexes: bad as never,
      });
      expect(r.valid, `expectedDisclosedIndexes=${String(bad)} must not verify`).toBe(false);
      expect(r.reason, `expectedDisclosedIndexes=${String(bad)}`).toBe('error');
      expect(r.detail).toContain('expectedDisclosedIndexes');
    }
  });
});

describe('proof size law: 144 + 32*(4 + U)', () => {
  it('holds for every disclosure size from 0 to 12', async () => {
    const { credential, issuer } = await fixture();
    const all = [...Array(SCHEMA_ATTRIBUTE_COUNT).keys()];
    for (let r = 0; r <= SCHEMA_ATTRIBUTE_COUNT; r++) {
      const proof = await derive(credential, all.slice(0, r), BASE_BINDING);
      const u = SCHEMA_ATTRIBUTE_COUNT - r;
      expect(proof.proof.length).toBe(144 + 32 * (4 + u));
      expect(proof.proof.length).toBe(expectedProofBytes(u));
      expect(await verify(proof, issuer.publicKey, BASE_BINDING, UNSAFE_NO_CHECKS)).toBe(true);
    }
  });

  it('reproduces the measured figures from the reference implementation', async () => {
    // 4 attributes: 1 disclosed -> 368 B, 2 -> 336 B, 3 -> 304 B.
    expect(expectedProofBytes(3)).toBe(368);
    expect(expectedProofBytes(2)).toBe(336);
    expect(expectedProofBytes(1)).toBe(304);
  });
});
