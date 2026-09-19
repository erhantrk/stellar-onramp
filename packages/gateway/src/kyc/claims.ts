/**
 *
 * This file is deliberately boring and deliberately shared. Every provider adapter calls
 * `deriveClaimSet`, so there is ONE place where a DOB becomes a boolean, ONE place that decides what
 *
 * THE DEFAULT FOR AN ABSENT FIELD IS `false`, ALWAYS, AND THAT IS THE ENTIRE POLICY. A provider that
 * omits `sanctionsHit` has not told us the applicant is clean; it has told us nothing. Defaulting an
 * unknown to `true` would mean a provider outage, a schema change on their side, or a typo in a field
 * name silently minting `notSanctioned=true` for everyone. Every branch below therefore reads as
 * "true only if the provider positively said so".
 *
 * The one place that is NOT a silent default is the age pair: an absent or unparseable DOB THROWS
 * rather than yielding `over18=false`, because `false` there is indistinguishable from a legitimately
 * 17-year-old applicant, and the operational response to the two is completely different. See
 * age.ts's `ageAtUtc`.
 */

import { CLAIM_INDEX, ISSUER_JURISDICTION_POLICY } from '@stellaronramp/identity';

import {
  CLAIM_JURISDICTION_OK,
  CLAIM_NOT_SANCTIONED,
  CLAIM_OVER_18,
  CLAIM_OVER_21,
} from '../chain/constants.js';
import { deriveAgeClaims } from './age.js';
import type { ClaimSet, KycStatus } from './provider.js';

export class ClaimDerivationError extends Error {
  override readonly name = 'ClaimDerivationError';
}

/**
 * The six boolean claim names, taken FROM identity's frozen schema rather than retyped.
 *
 * `CLAIM_INDEX` is the source of truth for the names AND for their positions. Retyping the names here
 * would create a second, unpinned copy, and schema.ts's own header warns why that is dangerous:
 * "adjacent boolean attributes differ only by POSITION so a mixed-up verifier is a real hazard".
 * The compile-time assertion at the bottom of this file makes a mismatch a BUILD failure.
 */
export const BOOLEAN_CLAIM_NAMES = Object.freeze([
  'over18',
  'over21',
  'notSanctioned',
  'notPep',
  'jurisdictionOk',
  'livenessOk',
] as const);

export type BooleanClaimName = (typeof BOOLEAN_CLAIM_NAMES)[number];

/**
 * Derive the six booleans. Pure, synchronous, no I/O, no clock read (the instant is a parameter so
 * the birthday boundary is testable), and it retains nothing.
 *
 * `status` IS NOT MUTATED and IS NOT STORED. The returned object is a fresh literal with six boolean
 * fields; there is no path by which a field of `status` reaches the output, which is what makes
 * "the ClaimSet contains no PII" a structural fact rather than a promise. test/kyc/pii.test.ts
 * asserts it mechanically anyway, in all four encodings including sha256.
 */
export function deriveClaimSet(status: KycStatus, at: Date): ClaimSet {
  if (status === null || typeof status !== 'object') {
    throw new ClaimDerivationError('refusing to derive claims from a non-object status');
  }
  if (status.answer !== 'approved') {
    // A rejected or still-pending applicant has no claims at all. Returning all-false would be a
    // credential asserting six false booleans, which is a valid credential that says nothing and
    // which the contract would refuse anyway (#12 EmptyClaims). Refusing here names the reason.
    throw new ClaimDerivationError(
      `refusing to derive claims for an applicant whose provider verdict is "${status.answer}"; ` +
        'only an approved applicant has claims, and an all-false credential is not a substitute ' +
        'for not issuing one',
    );
  }

  const age = deriveAgeClaims(status.dateOfBirth, at);

  return {
    over18: age.over18,
    over21: age.over21,
    // `=== true` and not truthiness: `sanctionsHit: "no"` from a sloppy provider payload is truthy,
    // and `!"no"` is false, so a truthiness read would set notSanctioned=false — safe. But
    // `sanctionsHit: undefined` with `!undefined` is TRUE, which would mint notSanctioned=true for a
    // field the provider never sent. Hence: notSanctioned is true only when the provider positively
    // said `sanctionsHit === false`.
    notSanctioned: status.sanctionsHit === false,
    notPep: status.pepHit === false,
    jurisdictionOk: jurisdictionAllowed(status.residenceCountry),
    livenessOk: status.livenessPassed === true,
  };
}

/**
 * Is the residence country inside the issuer's published jurisdiction policy?
 *
 * `ISSUER_JURISDICTION_POLICY` comes from identity's schema.ts, where it is documented as a PUBLIC
 * because a country plus a birth year plus a wallet is close to a name. So the country enters here,
 * decides one bit, and leaves. It is not returned, not persisted and not logged.
 *
 * An absent or malformed country is `false`, per the module's absent-means-no policy.
 */
export function jurisdictionAllowed(country: string | undefined): boolean {
  if (typeof country !== 'string') return false;
  // Exact, uppercase, two letters. No trim and no case-fold: a provider that sends " de " or "de"
  // has a field-mapping bug on their side or ours, and silently accepting it means the policy set is
  // wider than the published one. ISO-3166-1 alpha-2 is uppercase by definition.
  if (!/^[A-Z]{2}$/.test(country)) return false;
  return ISSUER_JURISDICTION_POLICY.includes(country);
}

/**
 * The frozen on-chain bitmap positions the provider verdict maps onto. The chain carries FOUR of the
 * six booleans (`lib.rs`: over18, over21, notSanctioned, jurisdictionOk); `notPep` and `livenessOk`
 * live only in the BBS+ credential, because the contract's u32 was frozen before they existed and no
 * wire-format change is in scope.
 *
 * THAT ASYMMETRY IS LOAD-BEARING AND EASY TO MISREAD: a relying party checking the on-chain bitmap
 * alone learns nothing about PEP status or liveness. Only a BBS+ proof carries those. Anyone building
 * a gate on the bitmap and calling it "full KYC" is wrong, and this comment is where they find out.
 */
export const CLAIM_BIT_BY_NAME: Readonly<Partial<Record<BooleanClaimName, number>>> = Object.freeze({
  over18: CLAIM_OVER_18,
  over21: CLAIM_OVER_21,
  notSanctioned: CLAIM_NOT_SANCTIONED,
  jurisdictionOk: CLAIM_JURISDICTION_OK,
});

/** Claim names that exist in the credential but have NO on-chain bit. Named, not implied. */
export const CLAIMS_WITHOUT_CHAIN_BITS: readonly BooleanClaimName[] = Object.freeze([
  'notPep',
  'livenessOk',
]);

/**
 * Project a `ClaimSet` onto the u32 the contract stores.
 *
 * A false claim contributes NO BIT rather than a zero bit, which is the same thing numerically and a
 * different thing operationally: the contract refuses `claims == 0` outright (#12 `EmptyClaims`), so
 * an applicant who is approved but over18=false and jurisdictionOk=false produces 0 and is refused on
 * chain rather than attested with an empty bitmap. That refusal is correct and this function does not
 * paper over it — it returns 0 and lets the chain signer's pre-flight guard name the error.
 */
export function claimBitmap(claims: ClaimSet): number {
  let bitmap = 0;
  for (const name of BOOLEAN_CLAIM_NAMES) {
    const bit = CLAIM_BIT_BY_NAME[name];
    if (bit === undefined) continue;
    if (claims[name]) bitmap |= bit;
  }
  return bitmap >>> 0;
}

/* -------------------------------------------------------------------------- */
/* Compile-time pin against identity's frozen schema.                          */
/* -------------------------------------------------------------------------- */

/**
 * If identity ever renames a boolean claim, adds a seventh, or drops one, one of these stops being
 * `never` and the package stops compiling. That is the point: a typo or a drifted name is a silently
 * WRONG credential — the BBS+ signature would be perfectly valid over the wrong message — and the
 * only cheap defence is to make the name set a type-level fact rather than a string literal.
 *
 * `ClaimSet`'s keys and `BOOLEAN_CLAIM_NAMES` are checked against each other too, so the runtime
 * array cannot drift from the interface.
 */
type IdentityBooleanClaims = Exclude<
  keyof typeof CLAIM_INDEX,
  | 'schemaVersion'
  | 'issuerId'
  | 'revocationIndex'
  | 'issuedAt'
  | 'expiresAt'
  | 'subjectBinding'
>;
type MissingFromOurs = Exclude<IdentityBooleanClaims, BooleanClaimName>;
type ExtraInOurs = Exclude<BooleanClaimName, IdentityBooleanClaims>;
type MissingFromClaimSet = Exclude<BooleanClaimName, keyof ClaimSet>;
type ExtraInClaimSet = Exclude<keyof ClaimSet, BooleanClaimName>;

const _noneMissing: MissingFromOurs extends never ? true : false = true;
const _noneExtra: ExtraInOurs extends never ? true : false = true;
const _claimSetComplete: MissingFromClaimSet extends never ? true : false = true;
const _claimSetTight: ExtraInClaimSet extends never ? true : false = true;
void _noneMissing;
void _noneExtra;
void _claimSetComplete;
void _claimSetTight;
