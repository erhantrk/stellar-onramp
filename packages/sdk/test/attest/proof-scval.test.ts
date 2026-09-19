/**
 * `bbsProofScVal` — the wire form the host actually accepts. The assertions pin what the measured
 * block documents: scvMap with scvSymbol KEYS (not scvString — nativeToScVal would emit those and
 * a #[contracttype] struct decodes from symbols only), ascending byte order, exactly eight fields.
 *
 * Uses a REAL derived proof (test/helpers.ts): splitProof decompresses G1 points with curve
 * validation, so byte-faked blobs cannot drive this builder.
 */

import { beforeAll, describe, expect, it } from 'vitest';

import { BBS_PROOF_FIELD_ORDER, bbsProofScVal } from '../../src/index.js';
import { fixture } from '../helpers.js';

import { expectedProofBytes, splitProof, type SorobanProof } from '@stellaronramp/identity';
import { scValToNative, xdr } from '@stellar/stellar-sdk';

describe('bbsProofScVal', () => {
  let sp: SorobanProof;
  let proofBytes: Uint8Array;
  let entries: ReturnType<xdr.ScVal['map']> & object;
  let scVal: xdr.ScVal;

  beforeAll(async () => {
    const f = await fixture();
    proofBytes = f.proof.proof;
    sp = splitProof(proofBytes);
    scVal = bbsProofScVal(sp);
    // An scvMap's entries are non-null by construction here; unwrap once and move on.
    const maybeEntries = scVal.map();
    if (maybeEntries === undefined || maybeEntries === null) {
      throw new Error('scvMap carried no entries');
    }
    entries = maybeEntries;
  });

  it('the fixture proof has the gate-predicate shape: R=8 disclosed, U=4 → 400 bytes', () => {
    expect(sp.undisclosedCount).toBe(4);
    expect(proofBytes.length).toBe(expectedProofBytes(sp.undisclosedCount));
    expect(proofBytes.length).toBe(400);
  });

  it('is an scvMap', () => {
    expect(scVal.switch()).toBe(xdr.ScValType.scvMap());
  });

  it('has exactly eight entries — a missing field is UnexpectedSize on chain, not a type error', () => {
    expect(entries.length).toBe(8);
  });

  it('every KEY is an scvSymbol, never scvString', () => {
    for (const entry of entries) {
      expect(entry.key().switch()).toBe(xdr.ScValType.scvSymbol());
    }
  });

  it('keys are in ASCENDING BYTE order (the host refusal is Error(Object, InvalidInput))', () => {
    const keys = entries.map((e) => e.key().sym());
    expect(keys).toEqual([...BBS_PROOF_FIELD_ORDER]);
    for (let i = 1; i < keys.length; i++) {
      const prev = Buffer.from(keys[i - 1] as string, 'utf8');
      const cur = Buffer.from(keys[i] as string, 'utf8');
      expect(Buffer.compare(prev, cur)).toBeLessThan(0);
    }
  });

  it('the value shapes match the SorobanProof fields (96-byte points, 32-byte scalars, m_hat vec)', () => {
    const byKey = new Map(entries.map((e) => [e.key().sym(), e.val()]));
    expect((byKey.get('a_bar') as xdr.ScVal).bytes().length).toBe(96);
    expect((byKey.get('b_bar') as xdr.ScVal).bytes().length).toBe(96);
    expect((byKey.get('d') as xdr.ScVal).bytes().length).toBe(96);
    expect((byKey.get('e_hat') as xdr.ScVal).bytes().length).toBe(32);
    expect((byKey.get('r1_hat') as xdr.ScVal).bytes().length).toBe(32);
    expect((byKey.get('r3_hat') as xdr.ScVal).bytes().length).toBe(32);
    expect((byKey.get('challenge') as xdr.ScVal).bytes().length).toBe(32);
    const mHat = byKey.get('m_hat') as xdr.ScVal;
    expect(mHat.switch()).toBe(xdr.ScValType.scvVec());
    expect(mHat.vec()!.length).toBe(sp.mHat.length);
    for (const m of mHat.vec()!) expect(m.bytes().length).toBe(32);
  });

  it('round-trips through scValToNative into an object with exactly the eight contract names', () => {
    const native = scValToNative(scVal) as Record<string, unknown>;
    expect(Object.keys(native).sort()).toEqual([...BBS_PROOF_FIELD_ORDER].sort());
  });
});
