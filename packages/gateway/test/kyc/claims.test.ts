/**
 * K3 claim derivation. The whole privacy design in one function: PII in, six booleans out, PII gone.
 *
 * THE POLICY UNDER TEST, and it is the entire security argument: an absent field is `false`, ALWAYS.
 * A provider that omits `sanctionsHit` has not told us the applicant is clean; it has told us
 * nothing. Defaulting an unknown to `true` would mean a provider outage, a schema change on their
 * side, or a typo in a field name silently minting `notSanctioned=true` for everyone.
 */

import { CLAIM_INDEX, ISSUER_JURISDICTION_POLICY } from '@stellaronramp/identity';
import { describe, expect, it } from 'vitest';

import {
  BOOLEAN_CLAIM_NAMES,
  CLAIMS_WITHOUT_CHAIN_BITS,
  CLAIM_BIT_BY_NAME,
  ClaimDerivationError,
  claimBitmap,
  deriveClaimSet,
  jurisdictionAllowed,
} from '../../src/kyc/claims.js';
import {
  CLAIM_JURISDICTION_OK,
  CLAIM_NOT_SANCTIONED,
  CLAIM_OVER_18,
  CLAIM_OVER_21,
} from '../../src/chain/constants.js';
import type { ClaimSet, KycStatus } from '../../src/kyc/provider.js';

const AT = new Date('2026-09-19T12:00:00.000Z');

/** An approved applicant with every field the provider could positively assert. */
function fullStatus(over: Partial<KycStatus> = {}): KycStatus {
  return {
    provider: 'kyc-provider',
    providerRefId: 'applicant-1',
    answer: 'approved',
    dateOfBirth: '1994-03-11',
    residenceCountry: 'DE',
    sanctionsHit: false,
    pepHit: false,
    livenessPassed: true,
    ...over,
  };
}

describe('the six claim names come FROM identity\'s frozen schema, not from a retyped literal', () => {
  it('matches identity\'s boolean claim names exactly, in schema index order', () => {
    // schema.ts warns that adjacent boolean attributes differ only by POSITION, so a drifted name is
    // a silently WRONG credential whose BBS+ signature verifies perfectly.
    expect([...BOOLEAN_CLAIM_NAMES]).toEqual([
      'over18',
      'over21',
      'notSanctioned',
      'notPep',
      'jurisdictionOk',
      'livenessOk',
    ]);
    const indexes = BOOLEAN_CLAIM_NAMES.map((n) => CLAIM_INDEX[n]);
    expect(indexes).toEqual([6, 7, 8, 9, 10, 11]);
    // Strictly ascending: the array order IS the schema order.
    expect(indexes).toEqual([...indexes].sort((a, b) => a - b));
  });

  it('is exactly the set of CLAIM_INDEX keys that are not metadata (no seventh, none missing)', () => {
    const metadata = new Set([
      'schemaVersion',
      'issuerId',
      'revocationIndex',
      'issuedAt',
      'expiresAt',
      'subjectBinding',
    ]);
    const identityBooleans = Object.keys(CLAIM_INDEX).filter((k) => !metadata.has(k));
    expect([...BOOLEAN_CLAIM_NAMES].sort()).toEqual(identityBooleans.sort());
    expect(Object.keys(CLAIM_INDEX)).toHaveLength(12);
  });

  it('uses camelCase, because THE CODE WINS over the design\'s snake_case table', () => {
    // CLAIM_INDEX is camelCase. Importing the names rather than retyping them is what settles it.
    expect(BOOLEAN_CLAIM_NAMES).toContain('over18');
    expect(BOOLEAN_CLAIM_NAMES).not.toContain('over_18');
    expect(BOOLEAN_CLAIM_NAMES).toContain('notSanctioned');
    expect(BOOLEAN_CLAIM_NAMES).not.toContain('not_sanctioned');
  });
});

describe('ABSENT MEANS FALSE, for every field, always', () => {
  it('derives all six from a fully-populated approved status', () => {
    expect(deriveClaimSet(fullStatus(), AT)).toEqual({
      over18: true,
      over21: true,
      notSanctioned: true,
      notPep: true,
      jurisdictionOk: true,
      livenessOk: true,
    });
  });

  it.each([
    ['sanctionsHit', 'notSanctioned'],
    ['pepHit', 'notPep'],
    ['livenessPassed', 'livenessOk'],
    ['residenceCountry', 'jurisdictionOk'],
  ] as const)('an ABSENT %s yields %s=false, never true', (field, claim) => {
    const status = fullStatus();
    const stripped = { ...status };
    delete (stripped as Record<string, unknown>)[field];
    expect(deriveClaimSet(stripped as KycStatus, AT)[claim]).toBe(false);
  });

  /**
   * The `=== true` / `=== false` discipline, not truthiness. `sanctionsHit: undefined` with
   * `!undefined` is TRUE, which would mint notSanctioned=true for a field the provider never sent.
   */
  it.each([
    ['undefined', undefined, false],
    ['null', null, false],
    ['the STRING "false"', 'false', false],
    ['the STRING "no"', 'no', false],
    ['the string "true"', 'true', false],
    ['0', 0, false],
    ['1', 1, false],
    ['an empty string', '', false],
    ['an object', {}, false],
    ['boolean true (a HIT)', true, false],
    ['boolean false (positively clean)', false, true],
  ])('notSanctioned is true only when sanctionsHit is positively boolean false: %s -> %s', (
    _label,
    sanctionsHit,
    expected,
  ) => {
    const status = { ...fullStatus(), sanctionsHit } as unknown as KycStatus;
    expect(deriveClaimSet(status, AT).notSanctioned).toBe(expected);
  });

  it.each([
    ['undefined', undefined, false],
    ['the string "true"', 'true', false],
    ['1', 1, false],
    ['boolean false', false, false],
    ['boolean true', true, true],
  ])('livenessOk is true only when livenessPassed is positively boolean true: %s -> %s', (
    _label,
    livenessPassed,
    expected,
  ) => {
    const status = { ...fullStatus(), livenessPassed } as unknown as KycStatus;
    expect(deriveClaimSet(status, AT).livenessOk).toBe(expected);
  });

  it('a sanctions HIT produces notSanctioned=false, which is the whole point of the claim', () => {
    expect(deriveClaimSet(fullStatus({ sanctionsHit: true }), AT).notSanctioned).toBe(false);
    expect(deriveClaimSet(fullStatus({ pepHit: true }), AT).notPep).toBe(false);
  });
});

describe('a non-approved applicant has NO claims, and that is an error not an all-false set', () => {
  it.each(['rejected', 'pending'] as const)('refuses to derive claims for a %s applicant', (answer) => {
    // An all-false credential is a valid credential that says nothing, and the contract refuses
    // claims==0 with #12 EmptyClaims anyway. Refusing here NAMES the reason.
    expect(() => deriveClaimSet(fullStatus({ answer }), AT)).toThrow(ClaimDerivationError);
    expect(() => deriveClaimSet(fullStatus({ answer }), AT)).toThrow(new RegExp(answer));
  });

  it.each([null, undefined, 42, 'approved', []])('refuses a non-object status: %s', (status) => {
    expect(() => deriveClaimSet(status as unknown as KycStatus, AT)).toThrow(ClaimDerivationError);
  });

  it('refuses an unknown verdict value rather than treating it as approved', () => {
    expect(() =>
      deriveClaimSet(fullStatus({ answer: 'APPROVED' as 'approved' }), AT),
    ).toThrow(ClaimDerivationError);
  });

  /** An absent or unparseable DOB THROWS; it is the one thing that is NOT a silent false. */
  it.each([undefined, null, '', 'not-a-date', '1994-3-11', 19940311])(
    'THROWS on an unusable DOB (%s) rather than yielding over18=false',
    (dateOfBirth) => {
      // `false` there is indistinguishable from a legitimately 17-year-old applicant, and the
      // operational response to the two is completely different.
      // Built as a mutable bag: `exactOptionalPropertyTypes` forbids assigning `undefined` to an
      // optional prop, and the ABSENT case is exactly what this table needs to cover.
      const status = { ...fullStatus() } as Record<string, unknown>;
      if (dateOfBirth === undefined) delete status['dateOfBirth'];
      else status['dateOfBirth'] = dateOfBirth;
      expect(() => deriveClaimSet(status as unknown as KycStatus, AT)).toThrow();
    },
  );

  it('does NOT echo the DOB when it throws on one', () => {
    let caught: Error | undefined;
    try {
      deriveClaimSet(fullStatus({ dateOfBirth: '2001/07/23' }), AT);
    } catch (e) {
      caught = e as Error;
    }
    expect(caught?.message).not.toContain('2001/07/23');
    expect(caught?.stack ?? '').not.toContain('2001/07/23');
  });
});

describe('jurisdiction is decided here and NEVER becomes a credential attribute', () => {
  it('accepts every country in identity\'s published ISSUER_JURISDICTION_POLICY', () => {
    expect(ISSUER_JURISDICTION_POLICY.length).toBeGreaterThan(0);
    for (const country of ISSUER_JURISDICTION_POLICY) {
      expect(jurisdictionAllowed(country), `${country} is in the policy`).toBe(true);
    }
  });

  it.each([
    ['a country outside the policy', 'US'],
    ['a lowercase form', 'de'],
    ['a mixed-case form', 'De'],
    ['a padded form', ' DE'],
    ['a trailing-space form', 'DE '],
    ['an alpha-3', 'DEU'],
    ['a one-letter value', 'D'],
    ['an empty string', ''],
    ['a numeric code', '276'],
    ['a regex-ish value', '.*'],
  ])('refuses %s, so the policy set is never wider than the published one', (_label, country) => {
    expect(jurisdictionAllowed(country)).toBe(false);
  });

  it.each([undefined, null, 42, {}, [], true])('refuses a non-string country: %s', (country) => {
    expect(jurisdictionAllowed(country as string | undefined)).toBe(false);
  });

  /**
   * name. So the country enters, decides one bit, and leaves.
   */
  it('the country does not appear in the derived ClaimSet in any form', () => {
    const claims = deriveClaimSet(fullStatus({ residenceCountry: 'DE' }), AT);
    expect(Object.keys(claims).sort()).toEqual([...BOOLEAN_CLAIM_NAMES].sort());
    expect(JSON.stringify(claims)).not.toContain('DE');
    expect(JSON.stringify(claims)).not.toContain('residenceCountry');
  });

  it('the derived ClaimSet is EXACTLY six booleans and carries nothing else', () => {
    const claims = deriveClaimSet(fullStatus(), AT);
    expect(Object.keys(claims)).toHaveLength(6);
    for (const [, value] of Object.entries(claims)) {
      expect(typeof value).toBe('boolean');
    }
  });

  it('does not mutate or retain its input', () => {
    const status = fullStatus();
    const before = JSON.stringify(status);
    deriveClaimSet(status, AT);
    expect(JSON.stringify(status)).toBe(before);
  });
});

describe('the on-chain bitmap projection, and the FOUR-of-SIX asymmetry', () => {
  it('maps the four claims that have a frozen on-chain bit', () => {
    expect(CLAIM_BIT_BY_NAME).toEqual({
      over18: CLAIM_OVER_18,
      over21: CLAIM_OVER_21,
      notSanctioned: CLAIM_NOT_SANCTIONED,
      jurisdictionOk: CLAIM_JURISDICTION_OK,
    });
    expect(Object.isFrozen(CLAIM_BIT_BY_NAME)).toBe(true);
  });

  /**
   * THE ASYMMETRY IS LOAD-BEARING AND EASY TO MISREAD. A relying party checking the on-chain bitmap
   * alone learns NOTHING about PEP status or liveness — only a BBS+ proof carries those.
   */
  it('notPep and livenessOk have NO on-chain bit, and that is named rather than implied', () => {
    expect([...CLAIMS_WITHOUT_CHAIN_BITS]).toEqual(['notPep', 'livenessOk']);
    for (const name of CLAIMS_WITHOUT_CHAIN_BITS) {
      expect(CLAIM_BIT_BY_NAME[name]).toBeUndefined();
    }
    // Every boolean claim is either mapped or explicitly named as unmapped. No third category.
    for (const name of BOOLEAN_CLAIM_NAMES) {
      const mapped = CLAIM_BIT_BY_NAME[name] !== undefined;
      const named = CLAIMS_WITHOUT_CHAIN_BITS.includes(name);
      expect(mapped !== named, `${name} must be exactly one of mapped / named-unmapped`).toBe(true);
    }
  });

  it('a credential asserting ONLY notPep and livenessOk projects to bitmap 0', () => {
    const claims: ClaimSet = {
      over18: false,
      over21: false,
      notSanctioned: false,
      notPep: true,
      jurisdictionOk: false,
      livenessOk: true,
    };
    // 0 is what the contract refuses with #12 EmptyClaims. claimBitmap returns it honestly rather
    // than papering over it.
    expect(claimBitmap(claims)).toBe(0);
  });

  it('ORs exactly the set bits and nothing else, for all 64 combinations', () => {
    for (let mask = 0; mask < 64; mask += 1) {
      const claims = Object.fromEntries(
        BOOLEAN_CLAIM_NAMES.map((n, i) => [n, (mask & (1 << i)) !== 0]),
      ) as unknown as ClaimSet;
      let expected = 0;
      for (const name of BOOLEAN_CLAIM_NAMES) {
        const bit = CLAIM_BIT_BY_NAME[name];
        if (bit !== undefined && claims[name]) expected |= bit;
      }
      expect(claimBitmap(claims)).toBe(expected >>> 0);
    }
  });

  it('always returns an unsigned 32-bit integer', () => {
    const all: ClaimSet = {
      over18: true,
      over21: true,
      notSanctioned: true,
      notPep: true,
      jurisdictionOk: true,
      livenessOk: true,
    };
    const bitmap = claimBitmap(all);
    expect(Number.isInteger(bitmap)).toBe(true);
    expect(bitmap).toBeGreaterThan(0);
    expect(bitmap).toBeLessThanOrEqual(0xffff_ffff);
    expect(bitmap).toBe(bitmap >>> 0);
  });
});
