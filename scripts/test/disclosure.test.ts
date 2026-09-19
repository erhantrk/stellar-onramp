import { describe, expect, it } from 'vitest';

import { parseDisclosure } from '../onboard/portal-api.js';

describe('the claims a holder chooses to disclose', () => {
  it('defaults to the gate pair when the field is absent', () => {
    expect(parseDisclosure(undefined)).toEqual(['over18', 'notSanctioned']);
  });

  it('keeps a valid selection, in the order given, without duplicates', () => {
    expect(parseDisclosure(['over21', 'over18', 'over21'])).toEqual(['over21', 'over18']);
  });

  it('accepts a credential-only claim as long as one chain-backed claim rides along', () => {
    expect(parseDisclosure(['over18', 'notPep'])).toEqual(['over18', 'notPep']);
  });

  it('refuses an unknown claim name rather than silently dropping it', () => {
    expect(() => parseDisclosure(['over18', 'overNine'])).toThrow(/not a disclosable claim/);
  });

  it('refuses a non-array', () => {
    expect(() => parseDisclosure('over18')).toThrow(/must be an array/);
  });

  it('refuses an empty selection', () => {
    expect(() => parseDisclosure([])).toThrow(/at least one claim/);
  });

  it('refuses a selection the claim record cannot carry', () => {
    // notPep and livenessOk have no bit in the contract's u32, so a record would be empty and
    // attest_bbs would refuse it on chain. Saying so here costs no wallet deployment.
    expect(() => parseDisclosure(['notPep', 'livenessOk'])).toThrow(/at least one of those/);
  });
});
