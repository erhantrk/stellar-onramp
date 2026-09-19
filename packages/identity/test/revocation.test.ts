/**
 * Revocation, end to end through `verifyDetailed` / `checkPredicate`.
 *
 * `gateOnrampPredicate()` discloses it, and until now NOTHING consumed it. A credential could be
 * revoked off-chain and every verifier in the system would still answer `valid: true`.
 *
 * The two properties that matter here and are easy to get wrong:
 *   1. supplying a status list over a proof that hides index 2 must FAIL, never silently pass;
 *   2. a status list we cannot read (short, wrong purpose, corrupt, unreachable) must FAIL, never
 *      be read as "not revoked".
 */

import { describe, expect, it } from 'vitest';

import {
  MINIMUM_STATUS_LIST_ENTRIES,
  ReplayGuard,
  UNSAFE_NO_CHECKS,
  UNSAFE_SKIP,
  checkPredicate,
  credentialAudit,
  encodeStatusList,
  gateOnrampPredicate,
  generateIssuerKeyPair,
  issue,
  issuerIdFromPublicKey,
  prove,
  standardOnrampPredicate,
  verifyDetailed,
  type BitstringStatusList,
  type Proof,
  type StatusListRequest,
} from '../src/index.js';
import { BASE_BINDING, ISSUER_SEED, claimsFor } from './helpers.js';


const REVOKED_AT = 4242; // == claimsFor()'s revocationIndex

async function gateFixture(): Promise<{ publicKey: Uint8Array; proof: Proof }> {
  const kp = await generateIssuerKeyPair(ISSUER_SEED);
  const cred = await issue(claimsFor(kp.publicKey), kp.secretKey);
  return { publicKey: kp.publicKey, proof: await prove(cred, gateOnrampPredicate(), BASE_BINDING) };
}

const liveList = (): Promise<BitstringStatusList> =>
  encodeStatusList({ statusPurpose: 'revocation', set: [7] });
const revokedList = (): Promise<BitstringStatusList> =>
  encodeStatusList({ statusPurpose: 'revocation', set: [REVOKED_AT] });

describe('revocation is enforced', () => {
  it('rejects a credential whose status-list bit is set', async () => {
    const { publicKey, proof } = await gateFixture();
    const r = await checkPredicate(proof, gateOnrampPredicate(), publicKey, BASE_BINDING, {
      ...UNSAFE_NO_CHECKS,
      statusList: await revokedList(),
    });
    expect(r.valid).toBe(false);
    expect(r.reason).toBe('revoked');
    expect(r.detail).toContain(String(REVOKED_AT));
  });

  it('accepts the same credential against a list where its bit is clear', async () => {
    const { publicKey, proof } = await gateFixture();
    const r = await checkPredicate(proof, gateOnrampPredicate(), publicKey, BASE_BINDING, {
      ...UNSAFE_NO_CHECKS,
      statusList: await liveList(),
    });
    expect(r.valid).toBe(true);
    expect(r.claims?.revocationIndex).toBe(REVOKED_AT);
  });

  it('is the ONLY thing standing between a revoked holder and a green light', async () => {
    // Delete the status-list block from verifyDetailed and this test goes green where it should
    // be red — the same proof, the same revoked list, the check switched off by name.
    const { publicKey, proof } = await gateFixture();
    const revoked = await revokedList();
    expect(
      (
        await checkPredicate(proof, gateOnrampPredicate(), publicKey, BASE_BINDING, {
          ...UNSAFE_NO_CHECKS,
          statusList: revoked,
        })
      ).reason,
    ).toBe('revoked');
    expect(
      (
        await checkPredicate(proof, gateOnrampPredicate(), publicKey, BASE_BINDING, {
          ...UNSAFE_NO_CHECKS,
          statusList: UNSAFE_SKIP,
        })
      ).valid,
    ).toBe(true);
  });

  it('handles suspension when asked for it, and only when asked', async () => {
    const { publicKey, proof } = await gateFixture();
    const suspended = await encodeStatusList({
      statusPurpose: 'suspension',
      set: [REVOKED_AT],
    });
    const asked = await checkPredicate(proof, gateOnrampPredicate(), publicKey, BASE_BINDING, {
      ...UNSAFE_NO_CHECKS,
      statusList: suspended,
      statusPurpose: 'suspension',
    });
    expect(asked.reason).toBe('revoked');
    expect(asked.detail).toContain('suspended');

    const unasked = await checkPredicate(proof, gateOnrampPredicate(), publicKey, BASE_BINDING, {
      ...UNSAFE_NO_CHECKS,
      statusList: suspended,
    });
    expect(unasked.valid).toBe(false);
    expect(unasked.reason).toBe('status-list-invalid');
    expect(unasked.detail).toContain('mismatch');
  });

  it('does not burn the replay nonce when the credential is revoked', async () => {
    // Nonce consumption is last for a reason: otherwise a bystander who learns a nonce could
    // grief a holder by presenting a proof that was going to fail anyway.
    const { publicKey, proof } = await gateFixture();
    const guard = new ReplayGuard();
    const revoked = await checkPredicate(proof, gateOnrampPredicate(), publicKey, BASE_BINDING, {
      ...UNSAFE_NO_CHECKS,
      statusList: await revokedList(),
      replayGuard: guard,
    });
    expect(revoked.reason).toBe('revoked');
    // The nonce survived, so a re-issued (unrevoked) list still verifies with the same guard.
    const after = await checkPredicate(proof, gateOnrampPredicate(), publicKey, BASE_BINDING, {
      ...UNSAFE_NO_CHECKS,
      statusList: await liveList(),
      replayGuard: guard,
    });
    expect(after.valid).toBe(true);
  });
});

describe('revocation FAILS CLOSED', () => {
  it('rejects when a status list is supplied but index 2 is not disclosed', async () => {
    // The dangerous shape, exactly as for currentTime/index 4 and expectedSubjectBinding/index 5:
    // a caller who asked for revocation checking and got `valid: true` without one having
    // happened is worse off than a caller who was told the option does not exist.
    const kp = await generateIssuerKeyPair(ISSUER_SEED);
    const cred = await issue(claimsFor(kp.publicKey), kp.secretKey);
    const proof = await prove(cred, standardOnrampPredicate(), BASE_BINDING);
    expect(proof.disclosedIndexes).not.toContain(2);

    const r = await checkPredicate(proof, standardOnrampPredicate(), kp.publicKey, BASE_BINDING, {
      ...UNSAFE_NO_CHECKS,
      statusList: await liveList(),
    });
    expect(r.valid).toBe(false);
    expect(r.reason).toBe('disclosure-shape');
    expect(r.detail).toContain('revocationIndex');
  });

  it('fails closed for a resolver too, not only for a literal list', async () => {
    const kp = await generateIssuerKeyPair(ISSUER_SEED);
    const cred = await issue(claimsFor(kp.publicKey), kp.secretKey);
    const proof = await prove(cred, standardOnrampPredicate(), BASE_BINDING);
    let called = 0;
    const r = await checkPredicate(proof, standardOnrampPredicate(), kp.publicKey, BASE_BINDING, {
      ...UNSAFE_NO_CHECKS,
      statusList: async () => {
        called++;
        return liveList();
      },
    });
    expect(r.reason).toBe('disclosure-shape');
    expect(called).toBe(0); // and we did not leak a lookup for an index we never verified
  });

  it('rejects a status list shorter than the spec minimum', async () => {
    const { publicKey, proof } = await gateFixture();
    // Hand-built below the floor; encodeStatusList refuses to make one this short.
    const shortBits = new Uint8Array(16);
    const cs = new CompressionStream('gzip');
    const w = cs.writable.getWriter();
    void w.write(shortBits);
    void w.close();
    const chunks: Uint8Array[] = [];
    const rd = cs.readable.getReader();
    for (;;) {
      const { done, value } = await rd.read();
      if (done) break;
      if (value !== undefined) chunks.push(value);
    }
    const encodedList = `u${Buffer.concat(chunks).toString('base64url')}`;

    const r = await checkPredicate(proof, gateOnrampPredicate(), publicKey, BASE_BINDING, {
      ...UNSAFE_NO_CHECKS,
      statusList: { statusPurpose: 'revocation', encodedList },
    });
    expect(r.valid).toBe(false);
    expect(r.reason).toBe('status-list-invalid');
    expect(r.detail).toContain('STATUS_LIST_LENGTH_ERROR');
  });

  it('rejects a corrupt encodedList', async () => {
    const { publicKey, proof } = await gateFixture();
    const r = await checkPredicate(proof, gateOnrampPredicate(), publicKey, BASE_BINDING, {
      ...UNSAFE_NO_CHECKS,
      statusList: { statusPurpose: 'revocation', encodedList: 'uAAAA' },
    });
    expect(r.reason).toBe('status-list-invalid');
  });

  it('rejects an unrecognised statusPurpose rather than reading it as "not revoked"', async () => {
    const { publicKey, proof } = await gateFixture();
    const live = await liveList();
    const r = await checkPredicate(proof, gateOnrampPredicate(), publicKey, BASE_BINDING, {
      ...UNSAFE_NO_CHECKS,
      statusList: { ...live, statusPurpose: 'refresh' },
    });
    expect(r.valid).toBe(false);
    expect(r.reason).toBe('status-list-invalid');
    expect(r.detail).toContain('unsupported statusPurpose');
  });

  it('rejects when the credential index is outside the list', async () => {
    const kp = await generateIssuerKeyPair(ISSUER_SEED);
    const cred = await issue(
      claimsFor(kp.publicKey, { revocationIndex: MINIMUM_STATUS_LIST_ENTRIES + 1 }),
      kp.secretKey,
    );
    const proof = await prove(cred, gateOnrampPredicate(), BASE_BINDING);
    const r = await checkPredicate(proof, gateOnrampPredicate(), kp.publicKey, BASE_BINDING, {
      ...UNSAFE_NO_CHECKS,
      statusList: await liveList(),
    });
    expect(r.valid).toBe(false);
    expect(r.reason).toBe('status-list-invalid');
    expect(r.detail).toContain('RANGE_ERROR');
  });

  it('rejects when the resolver throws (network down, 404, bad proof on the list VC)', async () => {
    const { publicKey, proof } = await gateFixture();
    const r = await checkPredicate(proof, gateOnrampPredicate(), publicKey, BASE_BINDING, {
      ...UNSAFE_NO_CHECKS,
      statusList: () => {
        throw new Error('status list endpoint returned 503');
      },
    });
    expect(r.valid).toBe(false);
    expect(r.reason).toBe('status-list-invalid');
    expect(r.detail).toContain('503');
  });
});

describe('the resolver callback is where the network lives', () => {
  it('is handed the disclosed revocationIndex, issuerId and purpose', async () => {
    const kp = await generateIssuerKeyPair(ISSUER_SEED);
    const cred = await issue(claimsFor(kp.publicKey), kp.secretKey);
    const proof = await prove(cred, gateOnrampPredicate(), BASE_BINDING);
    const seen: StatusListRequest[] = [];
    const r = await checkPredicate(proof, gateOnrampPredicate(), kp.publicKey, BASE_BINDING, {
      ...UNSAFE_NO_CHECKS,
      statusList: async (req) => {
        seen.push(req);
        return liveList();
      },
    });
    expect(r.valid).toBe(true);
    expect(seen).toEqual([
      {
        revocationIndex: REVOKED_AT,
        issuerId: issuerIdFromPublicKey(kp.publicKey),
        statusPurpose: 'revocation',
      },
    ]);
  });

  it('reports issuerId as undefined when index 1 is not disclosed', async () => {
    const kp = await generateIssuerKeyPair(ISSUER_SEED);
    const cred = await issue(claimsFor(kp.publicKey), kp.secretKey);
    // credentialAudit() discloses index 1; derive a narrower set on purpose.
    const narrow = { ...credentialAudit(), disclose: [2], expect: {} };
    const proof = await prove(cred, narrow, BASE_BINDING);
    const seen: StatusListRequest[] = [];
    const r = await checkPredicate(proof, narrow, kp.publicKey, BASE_BINDING, {
      ...UNSAFE_NO_CHECKS,
      statusList: async (req) => {
        seen.push(req);
        return liveList();
      },
    });
    expect(r.valid).toBe(true);
    expect(seen[0]?.issuerId).toBeUndefined();
    expect(seen[0]?.revocationIndex).toBe(REVOKED_AT);
  });

  it('runs AFTER ProofVerify, so a forged revocationIndex never reaches it', async () => {
    // The disclosed messages are attacker-controlled text until the BBS+ math has run. If the
    // status check moved above ProofVerify, a holder could name someone else's clear list slot.
    const { publicKey, proof } = await gateFixture();
    const forged: Proof = {
      ...proof,
      disclosedMessages: proof.disclosedMessages.map((m) =>
        m.startsWith('revocationIndex=') ? 'revocationIndex=7777' : m,
      ),
    };
    let called = 0;
    const r = await verifyDetailed(forged, publicKey, BASE_BINDING, {
      ...UNSAFE_NO_CHECKS,
      statusList: async () => {
        called++;
        return revokedList();
      },
    });
    expect(r.valid).toBe(false);
    expect(r.reason).toBe('bbs-invalid');
    expect(called).toBe(0);
  });
});
