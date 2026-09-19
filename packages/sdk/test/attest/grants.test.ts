/**
 * The claims-bitmap derivation — the COMPLETE mirror of lib.rs:1195-1227. What the tests pin:
 * each rule fires only on index AND exact message; a proof that does not disclose a boolean
 * CANNOT grant its bit (the narrowing-only property the contract enforces with InvalidProof);
 * and `gateOnrampPredicate`'s disclosure set derives exactly OVER_18|NOT_SANCTIONED, as
 * demo.ts:1584-1587 asserted live.
 */

import { describe, expect, it } from 'vitest';

import { ATTEST_GRANTS, deriveGrantedClaims } from '../../src/index.js';

import { CLAIM_INDEX } from '@stellaronramp/identity';
import {
  CLAIM_JURISDICTION_OK,
  CLAIM_NOT_SANCTIONED,
  CLAIM_OVER_18,
  CLAIM_OVER_21,
} from '@stellaronramp/gateway';

function proofWith(disclosed: Array<[number, string]>) {
  return {
    disclosedIndexes: disclosed.map(([i]) => i),
    disclosedMessages: disclosed.map(([, m]) => m),
  };
}

const GATE_DISCLOSURE: Array<[number, string]> = [
  [CLAIM_INDEX.schemaVersion, '1'],
  [CLAIM_INDEX.issuerId, 'a9daf8fd'.padEnd(64, '0')],
  [CLAIM_INDEX.revocationIndex, 'revocationIndex=4242'],
  [CLAIM_INDEX.issuedAt, 'issuedAt=1755000000'],
  [CLAIM_INDEX.expiresAt, 'expiresAt=1755864000'],
  [CLAIM_INDEX.subjectBinding, 'b'.repeat(64)],
  [6, 'over18=true'],
  [8, 'notSanctioned=true'],
];

describe('deriveGrantedClaims', () => {
  it('the table covers ALL FOUR derivable booleans — a partial mirror would be safe-but-silently-wrong', () => {
    expect(ATTEST_GRANTS.map(([index]) => index).sort((a, b) => a - b)).toEqual([6, 7, 8, 10]);
    expect(ATTEST_GRANTS).toEqual([
      [6, 'over18=true', CLAIM_OVER_18],
      [7, 'over21=true', CLAIM_OVER_21],
      [8, 'notSanctioned=true', CLAIM_NOT_SANCTIONED],
      [10, 'jurisdictionOk=true', CLAIM_JURISDICTION_OK],
    ]);
  });

  it('the gate predicate discloses indices {0..6,8}: derivation gives EXACTLY OVER_18|NOT_SANCTIONED', () => {
    const claims = deriveGrantedClaims(proofWith(GATE_DISCLOSURE));
    expect(claims).toBe(CLAIM_OVER_18 | CLAIM_NOT_SANCTIONED);
    // And NOT the bits demo.ts asserted could never be requested:
    expect(claims & CLAIM_OVER_21).toBe(0);
    expect(claims & CLAIM_JURISDICTION_OK).toBe(0);
  });

  it('fires on MESSAGE match, not merely on index presence', () => {
    // Index present but message tampered (only reachable over a failed signature check — but the
    // mirror must stay exact rather than trusting that).
    const claims = deriveGrantedClaims(proofWith([[6, 'over18=false'], [8, 'notSanctioned=true']]));
    expect(claims & CLAIM_OVER_18).toBe(0);
    expect(claims & CLAIM_NOT_SANCTIONED).toBe(CLAIM_NOT_SANCTIONED);
  });

  it('an undisclosed boolean grants NOTHING (narrowing-only by construction)', () => {
    const claims = deriveGrantedClaims(proofWith([[8, 'notSanctioned=true']]));
    expect(claims).toBe(CLAIM_NOT_SANCTIONED);
  });

  it('an empty disclosure grants nothing at all', () => {
    expect(deriveGrantedClaims(proofWith([]))).toBe(0);
  });

  it('widening is impossible BY CONSTRUCTION; every derivable bit needs its disclosure first', () => {
    // For every single-rule disclosure the result is exactly that one bit — no combination can
    // appear that was not disclosed.
    for (const [index, message, bit] of ATTEST_GRANTS) {
      const claims = deriveGrantedClaims(proofWith([[index, message]]));
      expect(claims).toBe(bit);
      for (const [, , otherBit] of ATTEST_GRANTS) {
        if (otherBit !== bit) expect(claims & otherBit).toBe(0);
      }
    }
  });

  it('all four booleans disclosed derive all four bits', () => {
    const claims = deriveGrantedClaims(
      proofWith([
        [6, 'over18=true'],
        [7, 'over21=true'],
        [8, 'notSanctioned=true'],
        [10, 'jurisdictionOk=true'],
      ]),
    );
    expect(claims).toBe(CLAIM_OVER_18 | CLAIM_OVER_21 | CLAIM_NOT_SANCTIONED | CLAIM_JURISDICTION_OK);
  });
});
