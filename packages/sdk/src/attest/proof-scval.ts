/**
 * the 39-line evidence block below — it encodes behaviour MEASURED against the live gate, twice,
 * not read off source, and losing it re-invites exactly the wrong guess it documents.
 */

import type { SorobanProof } from '@stellaronramp/identity';
import { xdr } from '@stellar/stellar-sdk';

import { compareSorobanSymbol } from './symbol.js';
import { bytesScVal } from './scval.js';

/**
 * `BbsProof` on the wire: an `scvMap` with `scvSymbol` keys, sorted ASCENDING BY BYTES. The host
 * refuses an out-of-order map outright — `Error(Object, InvalidInput)`, "ScMap was not sorted by
 * key for conversion to host object" — so the ordering is not cosmetic.
 *
 * **Byte order, not packed-code order**, and that distinction is worth pinning down because the
 * encoding invites the opposite guess: Soroban packs a short symbol into 6-bit codes in which `_`
 * is 1 and the digits and capitals follow it, the reverse of their ASCII positions. Nothing
 * compares those packed codes. `Compare<ScVal>` sends `ScVal::Symbol` to `Compare<&[u8]>`
 * (`soroban-env-host-27.0.1/src/host/comparison.rs:315`), `Compare<SymbolStr>` goes through
 * `<SymbolStr as AsRef<[u8]>>` (ibid. `:203`), and `Ord for SymbolSmall`
 * (`soroban-env-common-27.0.1/src/symbol.rs:187`) compares the DECODED chars. All byte order.
 *
 * Measured against this very gate rather than read off the source, twice, with a two-key map:
 * `[r_hat, r1_hat]` (packed-code order) is refused by the HOST — "ScMap was not sorted by key";
 * `[r1_hat, r_hat]` (byte order) is accepted by the host and reaches the CONTRACT, which then
 * refuses it for having two fields instead of eight (`Error(Object, UnexpectedSize)`). Same
 * result for `[_x, 0x]` versus `[0x, _x]`. A comparator that ranked `_` below the digits would
 * therefore CAUSE the failure it looks like it prevents.
 *
 * So why build the map by hand instead of `nativeToScVal`? Not for the ordering — its JS string
 * sort already IS byte order for `[A-Za-z0-9_]` names. For the key TYPE: given a plain object it
 * emits `scvString` keys (checked: `nativeToScVal({r_hat, r1_hat, _z, A})` yields four
 * `scvString`s), and a `#[contracttype]` struct decodes from `scvSymbol` only, so such a map is
 * rejected before any field is looked at. Building it by hand also pins the key SET — `BbsProof`
 * has exactly these eight fields, and a missing one is the `UnexpectedSize` above rather than a
 * type error.
 *
 * @param p - the SPLIT proof (`splitProof(proof.proof)`), not raw bytes: splitting decompresses
 *            the three G1 points into the wire form the contract expects, and identity already
 *            asserts the total length law on the way through.
 */
export function bbsProofScVal(p: SorobanProof): xdr.ScVal {
  const fields: Array<[string, xdr.ScVal]> = [
    ['a_bar', bytesScVal(p.abar)],
    ['b_bar', bytesScVal(p.bbar)],
    ['d', bytesScVal(p.d)],
    ['e_hat', bytesScVal(p.eHat)],
    ['r1_hat', bytesScVal(p.r1Hat)],
    ['r3_hat', bytesScVal(p.r3Hat)],
    ['m_hat', xdr.ScVal.scvVec(p.mHat.map((m) => bytesScVal(m)))],
    ['challenge', bytesScVal(p.challenge)],
  ];
  fields.sort(([a], [b]) => compareSorobanSymbol(a, b));
  return xdr.ScVal.scvMap(
    fields.map(([k, v]) => new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol(k), val: v })),
  );
}

/**
 * The eight `BbsProof` field names in the order this module emits them — ascending BYTE order.
 * Written out literally (not derived at load) so a reader can eyeball it against the measured
 * host rule, with a load-time guard below that keeps the literal honest.
 *
 * Note the two pairs history got wrong before measuring: `challenge` sorts between `b_bar` and
 * `d` (not last), and `m_hat` sorts BEFORE `r1_hat` (not after `r3_hat` as demo.ts's insertion
 * order happened to list them).
 */
export const BBS_PROOF_FIELD_ORDER: readonly string[] = [
  'a_bar',
  'b_bar',
  'challenge',
  'd',
  'e_hat',
  'm_hat',
  'r1_hat',
  'r3_hat',
];

for (let i = 1; i < BBS_PROOF_FIELD_ORDER.length; i++) {
  const prev = BBS_PROOF_FIELD_ORDER[i - 1] as string;
  const cur = BBS_PROOF_FIELD_ORDER[i] as string;
  if (compareSorobanSymbol(prev, cur) >= 0) {
    throw new Error(`BBS_PROOF_FIELD_ORDER is not ascending at [${i}] ("${prev}" vs "${cur}")`);
  }
}
