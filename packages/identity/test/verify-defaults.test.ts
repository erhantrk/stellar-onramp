/**
 *
 * The old API was `verify(proof, pk, binding, revealedClaims?, options = {})`. The obvious
 * three-argument call therefore checked NOTHING beyond the BBS+ signature: not presentation
 * expiry, not credential expiry, not the subject, not revocation, not replay, and — because
 * reproduction was three lines:
 *
 *     const stale = { ...binding, ledgerExpiry: 1 };   // ancient
 *     await verify(proof, pk, stale);  // true
 *     await verify(proof, pk, stale);  // true  (replayed)
 *     await verify(proof, pk, stale);  // true  (replayed again)
 *
 * `VerifyOptions` is now a REQUIRED parameter with REQUIRED fields, so that reproduction no longer
 * compiles, and the only way back to the old behaviour is to name `UNSAFE_SKIP` out loud.
 *
 * If a future refactor makes any of these fields optional again, the `@ts-expect-error` lines
 * below stop erroring and `npm run typecheck` goes red. That is the point of them.
 */

import { describe, expect, it } from 'vitest';

import {
  ReplayGuard,
  UNSAFE_NO_CHECKS,
  UNSAFE_SKIP,
  checkPredicate,
  computeSubjectBinding,
  encodeStatusList,
  gateOnrampPredicate,
  generateIssuerKeyPair,
  issue,
  over18,
  prove,
  standardOnrampPredicate,
  verify,
  verifyDetailed,
  type ProofBinding,
} from '../src/index.js';
import { BASE_BINDING, ISSUER_SEED, claimsFor, fixture } from './helpers.js';


const STALE: ProofBinding = { ...BASE_BINDING, ledgerExpiry: 1 };
const NOW_LEDGER = 1_000_000;
const HOLDER_SALT = Uint8Array.from({ length: 32 }, (_, i) => 0x11 + i);
const NOW = 1_767_225_600; // 2026-01-01
const DEAD = { issuedAt: 1_546_300_800, expiresAt: 1_577_836_800 }; // 2019 -> 2020

describe('the stale-proof attack', () => {
  it('rejects the ancient proof on all three attempts', async () => {
    const { credential, issuer } = await fixture();
    const proof = await prove(credential, over18(), STALE);
    const guard = new ReplayGuard();

    const attempt = async (): ReturnType<typeof verifyDetailed> =>
      verifyDetailed(proof, issuer.publicKey, STALE, {
        currentLedger: NOW_LEDGER,
        currentTime: NOW,
        expectedSubjectBinding: UNSAFE_SKIP,
        statusList: UNSAFE_SKIP,
        replayGuard: guard,
        expectedClaims: { over18: true },
        expectedDisclosedIndexes: over18().disclose,
      });

    for (let i = 0; i < 3; i++) {
      const r = await attempt();
      expect(r.valid).toBe(false);
      expect(r.reason).toBe('expired');
    }
  });

  it('the ONLY way back to the old `true, true, true` is to say UNSAFE_SKIP by name', async () => {
    const { credential, issuer } = await fixture();
    const proof = await prove(credential, over18(), STALE);
    for (let i = 0; i < 3; i++) {
      expect(await verify(proof, issuer.publicKey, STALE, UNSAFE_NO_CHECKS)).toBe(true);
    }
  });

  it('a live ledger accepts the same proof against a live binding', async () => {
    const { credential, issuer } = await fixture();
    const proof = await prove(credential, over18(), BASE_BINDING);
    const r = await verifyDetailed(proof, issuer.publicKey, BASE_BINDING, {
      ...UNSAFE_NO_CHECKS,
      currentLedger: BASE_BINDING.ledgerExpiry,
    });
    expect(r.valid).toBe(true);
  });

  it('rejects a bogus currentLedger instead of quietly skipping the check', async () => {
    const { credential, issuer } = await fixture();
    const proof = await prove(credential, over18(), STALE);
    for (const currentLedger of [Number.NaN, -1, 1.5, Number.POSITIVE_INFINITY]) {
      const r = await verifyDetailed(proof, issuer.publicKey, STALE, {
        ...UNSAFE_NO_CHECKS,
        currentLedger,
      });
      expect(r.valid).toBe(false);
      expect(r.reason).toBe('error');
    }
  });

  it('rejects a bogus currentTime instead of quietly skipping the check', async () => {
    const { credential, issuer } = await fixture();
    const proof = await prove(credential, gateOnrampPredicate(), BASE_BINDING);
    const r = await verifyDetailed(proof, issuer.publicKey, BASE_BINDING, {
      ...UNSAFE_NO_CHECKS,
      currentTime: Number.NaN,
    });
    expect(r.valid).toBe(false);
    expect(r.reason).toBe('error');
  });

  it('replay is enforced when a guard is named, three attempts, one success', async () => {
    const { credential, issuer } = await fixture();
    const proof = await prove(credential, over18(), BASE_BINDING);
    const guard = new ReplayGuard();
    const opts = { ...UNSAFE_NO_CHECKS, currentLedger: NOW_LEDGER, replayGuard: guard };
    expect((await verifyDetailed(proof, issuer.publicKey, BASE_BINDING, opts)).valid).toBe(true);
    expect((await verifyDetailed(proof, issuer.publicKey, BASE_BINDING, opts)).reason).toBe('replayed');
    expect((await verifyDetailed(proof, issuer.publicKey, BASE_BINDING, opts)).reason).toBe('replayed');
  });
});

describe('the unsafe path does not compile', () => {
  it('every safety field is required, so omission is a type error', async () => {
    const { credential, issuer } = await fixture();
    const proof = await prove(credential, over18(), BASE_BINDING);

    // @ts-expect-error options is required on verifyDetailed().
    await verifyDetailed(proof, issuer.publicKey, BASE_BINDING);
    // @ts-expect-error options is required on verify() too.
    await verify(proof, issuer.publicKey, BASE_BINDING);
    // @ts-expect-error options is required on checkPredicate().
    await checkPredicate(proof, over18(), issuer.publicKey, BASE_BINDING);
    // @ts-expect-error an empty bag no longer satisfies VerifyOptions.
    await verifyDetailed(proof, issuer.publicKey, BASE_BINDING, {});
    // @ts-expect-error naming five of the six is still not enough; statusList is missing.
    await verifyDetailed(proof, issuer.publicKey, BASE_BINDING, {
      currentLedger: UNSAFE_SKIP,
      currentTime: UNSAFE_SKIP,
      expectedSubjectBinding: UNSAFE_SKIP,
      replayGuard: UNSAFE_SKIP,
      expectedClaims: UNSAFE_SKIP,
    });
    // @ts-expect-error the old positional `revealedClaims` argument is gone.
    await verify(proof, issuer.publicKey, BASE_BINDING, { over18: true }, UNSAFE_NO_CHECKS);

    expect(true).toBe(true);
  });
});

describe('a fully-specified gate verification', () => {
  it('names every check and passes', async () => {
    const kp = await generateIssuerKeyPair(ISSUER_SEED);
    const cred = await issue(
      claimsFor(kp.publicKey, {
        subjectBinding: computeSubjectBinding(BASE_BINDING.walletAddress, HOLDER_SALT),
      }),
      kp.secretKey,
    );
    const proof = await prove(cred, gateOnrampPredicate(), BASE_BINDING);
    const r = await checkPredicate(proof, gateOnrampPredicate(), kp.publicKey, BASE_BINDING, {
      currentLedger: BASE_BINDING.ledgerExpiry - 1,
      currentTime: NOW,
      expectedSubjectBinding: computeSubjectBinding(BASE_BINDING.walletAddress, HOLDER_SALT),
      statusList: await encodeStatusList({ statusPurpose: 'revocation', set: [] }),
      replayGuard: new ReplayGuard(),
    });
    expect(r.valid).toBe(true);
    expect(r.claims).toEqual({
      schemaVersion: '1',
      issuerId: cred.claims.issuerId,
      revocationIndex: cred.claims.revocationIndex,
      issuedAt: cred.claims.issuedAt,
      expiresAt: cred.claims.expiresAt,
      subjectBinding: cred.claims.subjectBinding,
      over18: true,
      notSanctioned: true,
    });
  });

  it('and each individual check can still veto it', async () => {
    const kp = await generateIssuerKeyPair(ISSUER_SEED);
    const cred = await issue(
      claimsFor(kp.publicKey, {
        ...DEAD,
        subjectBinding: computeSubjectBinding(BASE_BINDING.walletAddress, HOLDER_SALT),
      }),
      kp.secretKey,
    );
    const proof = await prove(cred, gateOnrampPredicate(), BASE_BINDING);
    const base = {
      currentLedger: BASE_BINDING.ledgerExpiry - 1,
      currentTime: DEAD.expiresAt - 1,
      expectedSubjectBinding: computeSubjectBinding(BASE_BINDING.walletAddress, HOLDER_SALT),
      statusList: await encodeStatusList({ statusPurpose: 'revocation', set: [] }),
      replayGuard: UNSAFE_SKIP,
    } as const;
    expect(
      (await checkPredicate(proof, gateOnrampPredicate(), kp.publicKey, BASE_BINDING, base)).valid,
    ).toBe(true);

    const vetoes: Array<[string, Record<string, unknown>]> = [
      ['expired', { currentLedger: BASE_BINDING.ledgerExpiry + 1 }],
      ['credential-expired', { currentTime: NOW }],
      ['subject-mismatch', { expectedSubjectBinding: 'ab'.repeat(32) }],
      [
        'revoked',
        {
          statusList: await encodeStatusList({
            statusPurpose: 'revocation',
            set: [cred.claims.revocationIndex],
          }),
        },
      ],
    ];
    for (const [reason, override] of vetoes) {
      const r = await checkPredicate(proof, gateOnrampPredicate(), kp.publicKey, BASE_BINDING, {
        ...base,
        ...override,
      });
      expect(r.reason, `override ${JSON.stringify(Object.keys(override))}`).toBe(reason);
    }
  });

  it('standardOnrampPredicate cannot satisfy the gate policy — it hides 2, 4 and 5', async () => {
    // Documents the tradeoff rather than hiding it: the minimum-disclosure predicate is
    // structurally incapable of expiry, subject or revocation checking, and now says so.
    const { credential, issuer } = await fixture();
    const proof = await prove(credential, standardOnrampPredicate(), BASE_BINDING);
    for (const override of [
      { currentTime: NOW },
      { expectedSubjectBinding: 'ab'.repeat(32) },
      { statusList: await encodeStatusList({ statusPurpose: 'revocation', set: [] }) },
    ]) {
      const r = await checkPredicate(
        proof,
        standardOnrampPredicate(),
        issuer.publicKey,
        BASE_BINDING,
        { ...UNSAFE_NO_CHECKS, ...override },
      );
      expect(r.valid).toBe(false);
      expect(r.reason).toBe('disclosure-shape');
    }
  });
});
