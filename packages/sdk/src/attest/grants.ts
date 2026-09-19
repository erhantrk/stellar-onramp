/**
 * The `claims` argument of `attest_bbs`, DERIVED from a proof's disclosed messages rather than
 * partial-mirror warning); the contract's own derivation lives at
 * this is a COPY, not a move.
 */

import { CLAIM_INDEX } from '@stellaronramp/identity';
import type { Proof } from '@stellaronramp/identity';

import {
  CLAIM_JURISDICTION_OK,
  CLAIM_NOT_SANCTIONED,
  CLAIM_OVER_18,
  CLAIM_OVER_21,
} from '@stellaronramp/gateway';

/**
 * `claims` is DERIVED by the contract from the disclosed messages and the argument may only
 * NARROW it — passing a bit the credential does not disclose as `name=true` is InvalidProof, not
 * a free claim. This is the COMPLETE mirror of that derivation, all four rules of it
 * (lib.rs:1195-1227), so the argument is computed rather than asserted: the gate predicate
 * discloses indices {0,1,2,3,4,5,6,8}, so index 7 (`over21`) and index 10 (`jurisdictionOk`) are
 * not on the table at all and neither bit can be requested — even though this credential's holder
 * (an omission can only narrow, which the contract permits) and silent, which is the problem: the
 * next person to widen `gateOnrampPredicate` would find the table lying about being a mirror.
 */
export const ATTEST_GRANTS: Array<readonly [number, string, number]> = [
  [CLAIM_INDEX.over18, 'over18=true', CLAIM_OVER_18],
  [CLAIM_INDEX.over21, 'over21=true', CLAIM_OVER_21],
  [CLAIM_INDEX.notSanctioned, 'notSanctioned=true', CLAIM_NOT_SANCTIONED],
  [CLAIM_INDEX.jurisdictionOk, 'jurisdictionOk=true', CLAIM_JURISDICTION_OK],
];

/**
 * Derive the `claims` bitmap a proof may honestly request: for each rule in
 * {@link ATTEST_GRANTS}, set its bit iff the proof DISCLOSES that index AND the disclosed
 * message is exactly the canonical `name=true` form the contract matches.
 *
 * Why the message is compared and not just the index: the contract re-derives its grantable set
 * from the disclosed MESSAGES (`lib.rs:1195-1227`), and a proof could in principle disclose a
 * DIFFERENT message at a boolean index (only by deriving it over a tampered schema — but then the
 * signature check refuses first; the comparison here keeps the mirror exact rather than trusting
 * that the signature check will always run first).
 *
 * The result is by construction a SUBSET of what the proof supports — this function cannot widen,
 * reviews of the subject-binding change hunted for (lib.rs:1176-1194).
 */
export function deriveGrantedClaims(proof: Pick<Proof, 'disclosedIndexes' | 'disclosedMessages'>): number {
  return ATTEST_GRANTS.reduce((bits, [index, message, bit]) => {
    const at = proof.disclosedIndexes.indexOf(index);
    return at !== -1 && proof.disclosedMessages[at] === message ? bits | bit : bits;
  }, 0);
}
