import { describe, expect, it } from 'vitest';

import {
  CLAIM_INDEX,
  CLAIM_SPECS,
  CLAIM_SPEC_BY_INDEX,
  MAX_SCHEMA_ATTRIBUTES,
  SCHEMA_ATTRIBUTE_COUNT,
  SchemaError,
  UNSAFE_NO_CHECKS,
  assertNoPiiDisclosed,
  decodeDisclosed,
  derive,
  encodeClaim,
  encodeClaims,
  normalizeIndexes,
  verify,
  verifyDetailed,
} from '../src/index.js';
import { BASE_BINDING, claimsFor, fixture } from './helpers.js';


describe('schema', () => {
  it('freezes the index assignment from the schema', () => {
    // If this test ever needs updating, you are breaking every issued credential and every
    // deployed verifier. Append at index 12+, do not renumber.
    expect(CLAIM_INDEX).toEqual({
      schemaVersion: 0,
      issuerId: 1,
      revocationIndex: 2,
      issuedAt: 3,
      expiresAt: 4,
      subjectBinding: 5,
      over18: 6,
      over21: 7,
      notSanctioned: 8,
      notPep: 9,
      jurisdictionOk: 10,
      livenessOk: 11,
    });
  });

  it('is dense, unique and within the on-chain attribute cap', () => {
    const indexes = CLAIM_SPECS.map((s) => s.index).sort((a, b) => a - b);
    expect(indexes).toEqual([...Array(SCHEMA_ATTRIBUTE_COUNT).keys()]);
    expect(new Set(indexes).size).toBe(SCHEMA_ATTRIBUTE_COUNT);
    expect(SCHEMA_ATTRIBUTE_COUNT).toBeLessThanOrEqual(MAX_SCHEMA_ATTRIBUTES);
  });

  it('stays inside the verified CPU budget at N=12', () => {
    const cpu = 41_980_626 + 1_471_918 * SCHEMA_ATTRIBUTE_COUNT;
    expect(cpu).toBe(59_643_642);
    expect(cpu / 400_000_000).toBeLessThan(0.25);
    // ...and 39 is genuinely the cap, 40 is not.
    expect(41_980_626 + 1_471_918 * MAX_SCHEMA_ATTRIBUTES).toBeLessThan(100_000_000);
    expect(41_980_626 + 1_471_918 * (MAX_SCHEMA_ATTRIBUTES + 1)).toBeGreaterThan(100_000_000);
  });

  it('carries no PII attribute at all', () => {
    expect(CLAIM_SPECS.every((s) => !s.pii)).toBe(true);
    const names = CLAIM_SPECS.map((s) => s.name.toLowerCase());
    for (const banned of ['dateofbirth', 'dob', 'givenname', 'familyname', 'documentnumber', 'nationality']) {
      expect(names).not.toContain(banned);
    }
  });

  it('embeds the attribute name in the signed bytes', async () => {
    const { issuer } = await fixture();
    const messages = encodeClaims(claimsFor(issuer.publicKey));
    expect(messages[CLAIM_INDEX.over18]).toBe('over18=true');
    expect(messages[CLAIM_INDEX.over21]).toBe('over21=true');
    // over18 and over21 are both `true` but their bytes differ — a positional mix-up cannot
    // pass unnoticed.
    expect(messages[CLAIM_INDEX.over18]).not.toBe(messages[CLAIM_INDEX.over21]);
  });

  it('round-trips disclosed messages', () => {
    const decoded = decodeDisclosed([CLAIM_INDEX.over18, CLAIM_INDEX.revocationIndex], [
      'over18=true',
      'revocationIndex=4242',
    ]);
    expect(decoded).toEqual({ over18: true, revocationIndex: 4242 });
  });

  it('rejects a message whose embedded name disagrees with its index', () => {
    expect(() => decodeDisclosed([CLAIM_INDEX.over18], ['over21=true'])).toThrow(SchemaError);
  });

  it('rejects non-canonical values', () => {
    expect(() => decodeDisclosed([CLAIM_INDEX.over18], ['over18=TRUE'])).toThrow(SchemaError);
    expect(() => decodeDisclosed([CLAIM_INDEX.revocationIndex], ['revocationIndex=007'])).toThrow(
      SchemaError,
    );
    expect(() => encodeClaim('over18', 'true' as unknown as boolean)).toThrow(SchemaError);
    expect(() => encodeClaim('revocationIndex', -1)).toThrow(SchemaError);
    expect(() => encodeClaim('issuerId', 'AB')).toThrow(SchemaError);
    expect(() => encodeClaim('issuerId', 'A'.repeat(64))).toThrow(SchemaError); // uppercase hex
  });

  it('rejects a claim set with a missing attribute', () => {
    const partial = { ...claimsFor(new Uint8Array(96)) } as Record<string, unknown>;
    delete partial.livenessOk;
    expect(() => encodeClaims(partial as never)).toThrow(SchemaError);
  });

  it('normalizes disclosure index sets and rejects malformed ones', () => {
    expect(normalizeIndexes([8, 6])).toEqual([6, 8]);
    expect(normalizeIndexes([])).toEqual([]);
    expect(() => normalizeIndexes([6, 6])).toThrow(SchemaError);
    expect(() => normalizeIndexes([12])).toThrow(SchemaError);
    expect(() => normalizeIndexes([-1])).toThrow(SchemaError);
    expect(() => normalizeIndexes([1.5])).toThrow(SchemaError);
  });
});

/**
 *
 * `derive()` has always run `assertNoPiiDisclosed` via `normalizeIndexes`. `verifyDetailed()` did
 * not, which meant the only side it policed was the side we control: a proof arrives from a
 * HOLDER, and a holder on an old or hostile SDK is the party the guard exists for.
 *
 * Schema v1 has no `pii: true` attribute, so the guard is a no-op and cannot be observed by
 * ordinary means — which is exactly how an asymmetry survives. These tests flip the flag on a real
 * attribute for the duration of one call and put it back, so the WIRING is measured rather than
 * assumed. Nothing else reads `pii`, so the blast radius of the flip is the guard itself.
 */
describe('assertNoPiiDisclosed is enforced on derive AND on verify', () => {
  /** Flip `pii` on one spec, run `fn`, restore. The spec objects are shared by reference. */
  async function withPiiOn<T>(index: number, fn: () => Promise<T>): Promise<T> {
    const spec = CLAIM_SPEC_BY_INDEX[index] as { pii: boolean } | undefined;
    if (spec === undefined) throw new Error(`no spec at index ${index}`);
    const before = spec.pii;
    spec.pii = true;
    try {
      return await fn();
    } finally {
      spec.pii = before;
    }
  }

  it('v1 declares nothing PII-bearing, so the guard is a no-op today', () => {
    expect(CLAIM_SPECS.some((s) => s.pii)).toBe(false);
    expect(() => assertNoPiiDisclosed([...Array(SCHEMA_ATTRIBUTE_COUNT).keys()])).not.toThrow();
  });

  it('derive() refuses to build a proof over a PII-bearing index', async () => {
    const { credential } = await fixture();
    await withPiiOn(CLAIM_INDEX.over18, async () => {
      await expect(derive(credential, [CLAIM_INDEX.over18], BASE_BINDING)).rejects.toThrow(
        /PII-bearing attribute "over18"/,
      );
      // ...and an index that is NOT flagged still derives, so the guard is selective.
      await expect(derive(credential, [CLAIM_INDEX.over21], BASE_BINDING)).resolves.toBeDefined();
    });
  });

  it('verifyDetailed() refuses a proof that discloses a PII-bearing index', async () => {
    const { credential, issuer } = await fixture();
    // Derived while the flag is OFF — this is the hostile-holder case: the proof is genuine and
    // cryptographically perfect, and the verifier's own policy is the only thing that says no.
    const proof = await derive(credential, [CLAIM_INDEX.over18], BASE_BINDING);
    expect(await verify(proof, issuer.publicKey, BASE_BINDING, UNSAFE_NO_CHECKS)).toBe(true);

    const r = await withPiiOn(CLAIM_INDEX.over18, () =>
      verifyDetailed(proof, issuer.publicKey, BASE_BINDING, UNSAFE_NO_CHECKS),
    );
    expect(r.valid).toBe(false);
    expect(r.reason).toBe('disclosure-shape');
    expect(r.detail).toMatch(/discloses a PII-bearing attribute.*"over18"/);

    // The flag is restored, so the same proof verifies again — the rejection was the guard and
    // not a side effect of the mutation.
    expect(await verify(proof, issuer.publicKey, BASE_BINDING, UNSAFE_NO_CHECKS)).toBe(true);
  });
});
