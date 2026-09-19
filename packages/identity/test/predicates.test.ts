import { describe, expect, it } from 'vitest';

import {
  UNSAFE_NO_CHECKS,
  CLAIM_INDEX,
  ISSUER_JURISDICTION_POLICY,
  PredicateError,
  ReplayGuard,
  allOf,
  checkPredicate,
  countryAllowed,
  derive,
  generateIssuerKeyPair,
  issue,
  livenessOk,
  notPep,
  notSanctioned,
  over18,
  over21,
  prove,
  standardOnrampPredicate,
  DISCLOSABLE_CLAIM_NAMES,
  claimPredicate,
  credentialAudit,
  gatePredicateFor,
} from '../src/index.js';
import { BASE_BINDING, ISSUER_SEED, OTHER_CONTRACT, claimsFor, fixture } from './helpers.js';


describe('predicates', () => {
  it('over18 discloses exactly one index and nothing else', async () => {
    const { credential, issuer } = await fixture();
    const p = over18();
    expect(p.disclose).toEqual([CLAIM_INDEX.over18]);
    const proof = await prove(credential, p, BASE_BINDING);
    expect(proof.disclosedIndexes).toEqual([CLAIM_INDEX.over18]);
    const r = await checkPredicate(proof, p, issuer.publicKey, BASE_BINDING, UNSAFE_NO_CHECKS);
    expect(r.valid).toBe(true);
    expect(r.claims).toEqual({ over18: true });
  });

  it('does not drag over21 along with over18 (anonymity-set hygiene, §7.4)', () => {
    expect(over18().disclose).not.toContain(CLAIM_INDEX.over21);
    expect(over21().disclose).toEqual([CLAIM_INDEX.over21]);
  });

  it('notSanctioned / notPep / livenessOk each expect true', async () => {
    const { credential, issuer } = await fixture();
    for (const p of [notSanctioned(), notPep(), livenessOk()]) {
      const proof = await prove(credential, p, BASE_BINDING);
      expect((await checkPredicate(proof, p, issuer.publicKey, BASE_BINDING, UNSAFE_NO_CHECKS)).valid).toBe(true);
    }
  });

  it('fails a predicate whose claim is false in the credential', async () => {
    const kp = await generateIssuerKeyPair(ISSUER_SEED);
    const cred = await issue(claimsFor(kp.publicKey, { over18: false }), kp.secretKey);
    const proof = await prove(cred, over18(), BASE_BINDING);
    const r = await checkPredicate(proof, over18(), kp.publicKey, BASE_BINDING, UNSAFE_NO_CHECKS);
    expect(r.valid).toBe(false);
    expect(r.reason).toBe('claim-mismatch');
  });

  it('standardOnrampPredicate is over18 AND notSanctioned, U=10, 592-byte proof', async () => {
    const { credential, issuer } = await fixture();
    const p = standardOnrampPredicate();
    expect(p.disclose).toEqual([CLAIM_INDEX.over18, CLAIM_INDEX.notSanctioned]);
    const proof = await prove(credential, p, BASE_BINDING);
    expect(proof.proof.length).toBe(592);
    expect((await checkPredicate(proof, p, issuer.publicKey, BASE_BINDING, UNSAFE_NO_CHECKS)).valid).toBe(true);
  });

  it('allOf merges disclosure sets and rejects conflicting expectations', () => {
    const merged = allOf(over18(), notSanctioned(), notPep());
    expect(merged.disclose).toEqual([
      CLAIM_INDEX.over18,
      CLAIM_INDEX.notSanctioned,
      CLAIM_INDEX.notPep,
    ]);
    expect(merged.expect).toEqual({ over18: true, notSanctioned: true, notPep: true });
    expect(() => allOf()).toThrow(PredicateError);

    const contrary = { label: 'x', disclose: [CLAIM_INDEX.over18], expect: { over18: false } };
    expect(() => allOf(over18(), contrary)).toThrow(PredicateError);
  });

  it('rejects a proof that discloses MORE than the predicate asked for', async () => {
    const { credential, issuer } = await fixture();
    const over = await derive(
      credential,
      [CLAIM_INDEX.over18, CLAIM_INDEX.over21, CLAIM_INDEX.notSanctioned],
      BASE_BINDING,
    );
    // Cryptographically fine, privacy-wise not.
    const r = await checkPredicate(over, standardOnrampPredicate(), issuer.publicKey, BASE_BINDING, UNSAFE_NO_CHECKS);
    expect(r.valid).toBe(false);
    expect(r.reason).toBe('disclosure-shape');
  });

  it('rejects a proof that discloses LESS than the predicate asked for', async () => {
    const { credential, issuer } = await fixture();
    const under = await derive(credential, [CLAIM_INDEX.over18], BASE_BINDING);
    expect(
      (await checkPredicate(under, standardOnrampPredicate(), issuer.publicKey, BASE_BINDING, UNSAFE_NO_CHECKS)).reason,
    ).toBe('disclosure-shape');
  });

  it('enforces binding, expiry and replay through checkPredicate', async () => {
    const { credential, issuer } = await fixture();
    const p = over18();
    const proof = await prove(credential, p, BASE_BINDING);
    const guard = new ReplayGuard();

    expect(
      (await checkPredicate(proof, p, issuer.publicKey, { ...BASE_BINDING, contractId: OTHER_CONTRACT }, UNSAFE_NO_CHECKS))
        .reason,
    ).toBe('binding-mismatch');
    expect(
      (await checkPredicate(proof, p, issuer.publicKey, BASE_BINDING, {
        ...UNSAFE_NO_CHECKS,
        currentLedger: 9_999_999,
      }))
        .reason,
    ).toBe('expired');
    expect((await checkPredicate(proof, p, issuer.publicKey, BASE_BINDING, {
      ...UNSAFE_NO_CHECKS,
      replayGuard: guard,
    })).valid).toBe(true);
    expect((await checkPredicate(proof, p, issuer.publicKey, BASE_BINDING, {
      ...UNSAFE_NO_CHECKS,
      replayGuard: guard,
    })).reason).toBe('replayed');
  });
});

describe('countryAllowed', () => {
  it('is satisfiable when the relying party accepts everything the issuer stamps', async () => {
    const { credential, issuer } = await fixture();
    const p = countryAllowed([...ISSUER_JURISDICTION_POLICY, 'US']);
    expect(p.disclose).toEqual([CLAIM_INDEX.jurisdictionOk]);
    const proof = await prove(credential, p, BASE_BINDING);
    expect((await checkPredicate(proof, p, issuer.publicKey, BASE_BINDING, UNSAFE_NO_CHECKS)).valid).toBe(true);
  });

  it('is UNSATISFIABLE over schema v1 when the allowlist is narrower than the issuer policy', () => {
    // Schema v1 has no country attribute; the credential only carries the issuer's boolean
    // verdict. Answering "is the holder in {DE, FR}" is impossible, so we throw rather than
    // return a predicate that silently proves something weaker.
    expect(() => countryAllowed(['DE', 'FR'])).toThrow(PredicateError);
    expect(() => countryAllowed(['DE', 'FR'])).toThrow(/unsatisfiable over schema v1/);
  });

  it('works against a narrow issuer policy', async () => {
    const { credential, issuer } = await fixture();
    const p = countryAllowed(['de', 'fr', 'nl'], { issuerPolicy: ['DE', 'NL'] });
    expect(p.label).toBe('countryAllowed(DE,FR,NL)');
    const proof = await prove(credential, p, BASE_BINDING);
    expect((await checkPredicate(proof, p, issuer.publicKey, BASE_BINDING, UNSAFE_NO_CHECKS)).valid).toBe(true);
  });

  it('fails when the issuer stamped jurisdictionOk=false', async () => {
    const kp = await generateIssuerKeyPair(ISSUER_SEED);
    const cred = await issue(claimsFor(kp.publicKey, { jurisdictionOk: false }), kp.secretKey);
    const p = countryAllowed(['DE'], { issuerPolicy: ['DE'] });
    const proof = await prove(cred, p, BASE_BINDING);
    expect((await checkPredicate(proof, p, kp.publicKey, BASE_BINDING, UNSAFE_NO_CHECKS)).reason).toBe('claim-mismatch');
  });

  it('rejects malformed country codes and empty allowlists', () => {
    expect(() => countryAllowed([])).toThrow(PredicateError);
    expect(() => countryAllowed(['DEU'], { issuerPolicy: ['DE'] })).toThrow(PredicateError);
    expect(() => countryAllowed(['D1'], { issuerPolicy: ['DE'] })).toThrow(PredicateError);
  });
});

describe('gatePredicateFor — the caller chooses which booleans to disclose', () => {
  it('always includes the metadata block, plus exactly the claims named', () => {
    const audit = credentialAudit().disclose;
    const p = gatePredicateFor(['over18']);
    expect(p.disclose).toEqual([...audit, CLAIM_INDEX.over18].sort((a, b) => a - b));
    expect(p.expect).toMatchObject({ over18: true });
  });

  it('a wider selection discloses more indexes and nothing beyond them', () => {
    const p = gatePredicateFor(['over18', 'over21', 'notSanctioned']);
    expect(p.disclose).toContain(CLAIM_INDEX.over21);
    expect(p.disclose).not.toContain(CLAIM_INDEX.notPep);
    expect(p.disclose).not.toContain(CLAIM_INDEX.livenessOk);
  });

  it('duplicates collapse and order does not matter', () => {
    const a = gatePredicateFor(['over18', 'over18', 'notSanctioned']);
    const b = gatePredicateFor(['notSanctioned', 'over18']);
    expect(a.disclose).toEqual(b.disclose);
  });

  it('an empty selection is refused rather than proving nothing', () => {
    expect(() => gatePredicateFor([])).toThrow(PredicateError);
  });

  it('an unknown claim name is refused', () => {
    // @ts-expect-error the name is not in DisclosableClaimName
    expect(() => claimPredicate('overNine')).toThrow(PredicateError);
  });

  it('every disclosable name builds a predicate over its own index', () => {
    for (const name of DISCLOSABLE_CLAIM_NAMES) {
      expect(claimPredicate(name).disclose).toEqual([CLAIM_INDEX[name]]);
    }
  });

  it('a proof over the chosen set discloses exactly that set', async () => {
    const { credential, issuer } = await fixture();
    const p = gatePredicateFor(['over18', 'over21']);
    const proof = await prove(credential, p, BASE_BINDING);
    expect(proof.disclosedIndexes).toEqual([...p.disclose].sort((a, b) => a - b));
    const r = await checkPredicate(proof, p, issuer.publicKey, BASE_BINDING, UNSAFE_NO_CHECKS);
    expect(r.valid).toBe(true);
  });
});
