/**
 * The twelve `attest_bbs` arguments, position by position — the wire order demo.ts:1594-1607
 * pins. The load-bearing assertion is position 10: the CREDENTIAL header, NOT the presentation
 * for two unrelated subjects).
 *
 * Uses a REAL issued credential and REAL derived proof (see test/helpers.ts): splitProof
 * decompresses G1 points with curve validation, so byte-faked proofs cannot drive this builder.
 */

import { utf8ToBytes } from '@noble/hashes/utils.js';
import { describe, expect, it } from 'vitest';

import {
  AttestError,
  attestBbsArgs,
  type AttestBbsArgsInput,
} from '../../src/index.js';
import { TEST_WALLET_C, fixture } from '../helpers.js';

import { CREDENTIAL_HEADER, presentationHeaderFor } from '@stellaronramp/identity';
import { scValToNative, xdr } from '@stellar/stellar-sdk';

async function input(overrides: Partial<AttestBbsArgsInput> = {}): Promise<AttestBbsArgsInput> {
  const f = await fixture();
  return {
    subject: TEST_WALLET_C,
    issuerId: f.issuerIdHex,
    claimsBitmap: 0b101, // OVER_18 | NOT_SANCTIONED
    expiresAt: 1_755_864_000,
    revocationEpoch: 0,
    revocationIndex: 4242,
    proof: f.proof,
    nonceHex: f.nonceHex,
    ledgerExpiry: 4_196_173,
    ...overrides,
  };
}

describe('attestBbsArgs', () => {
  it('emits exactly TWELVE positional arguments', async () => {
    expect(attestBbsArgs(await input()).length).toBe(12);
  });

  it('positions 1-6 and 11-12 carry the scalar arguments in contract order', async () => {
    const args = attestBbsArgs(await input());
    // 1 subject(Address)
    expect(scValToNative(args[0] as xdr.ScVal)).toBe(TEST_WALLET_C);
    // 2 issuer_id(bytes32)
    expect(Buffer.from((args[1] as xdr.ScVal).bytes()).toString('hex')).toBe(
      (await fixture()).issuerIdHex,
    );
    // 3 claims(u32)
    expect(scValToNative(args[2] as xdr.ScVal)).toBe(0b101);
    // 4 expires_at(u32)
    expect(scValToNative(args[3] as xdr.ScVal)).toBe(1_755_864_000);
    // 5 revocation_epoch(u32)
    expect(scValToNative(args[4] as xdr.ScVal)).toBe(0);
    // 6 revocation_index(u32)
    expect(scValToNative(args[5] as xdr.ScVal)).toBe(4242);
    // 11 nonce(bytes32)
    expect(Buffer.from((args[10] as xdr.ScVal).bytes()).toString('hex')).toBe('c'.repeat(64));
    // 12 ledger_expiry(u32)
    expect(scValToNative(args[11] as xdr.ScVal)).toBe(4_196_173);
  });

  it('position 7 is the BbsProof map with eight symbol keys', async () => {
    const args = attestBbsArgs(await input());
    const proofMap = args[6] as xdr.ScVal;
    expect(proofMap.switch()).toBe(xdr.ScValType.scvMap());
    const entries = proofMap.map()!; // an scvMap's entries are present by construction here
    expect(entries.length).toBe(8);
    for (const entry of entries) {
      expect(entry.key().switch()).toBe(xdr.ScValType.scvSymbol());
    }
  });

  it('positions 8-9 mirror the proof disclosure verbatim', async () => {
    const f = await fixture();
    const args = attestBbsArgs(await input());
    const indexes = scValToNative(args[7] as xdr.ScVal) as number[];
    const messages = (scValToNative(args[8] as xdr.ScVal) as Buffer[]).map((b) =>
      Buffer.from(b).toString('utf8'),
    );
    expect(indexes).toEqual([...f.proof.disclosedIndexes]);
    expect(messages).toEqual([...f.proof.disclosedMessages]);
  });

  it('position 10 is the CREDENTIAL header — NOT the presentation header', async () => {
    const f = await fixture();
    const args = attestBbsArgs(await input());
    const headerHex = Buffer.from((args[9] as xdr.ScVal).bytes()).toString('hex');
    expect(headerHex).toBe(Buffer.from(utf8ToBytes(CREDENTIAL_HEADER)).toString('hex'));
    // And explicitly NOT what a naive caller might compute instead:
    const presentationHeader = presentationHeaderFor(f.proof.binding);
    expect(headerHex).not.toBe(Buffer.from(presentationHeader).toString('hex'));
  });

  it('the proof bytes survive the round trip: position 7 decodes to the split of the derived proof', async () => {
    const f = await fixture();
    const args = attestBbsArgs(await input());
    const proofMap = args[6] as xdr.ScVal;
    const byKey = new Map(proofMap.map()!.map((e) => [e.key().sym(), e.val()]));
    // a_bar is a decompressed G1 point: 96 bytes, matching what splitProof produced.
    expect((byKey.get('a_bar') as xdr.ScVal).bytes().length).toBe(96);
    expect((byKey.get('challenge') as xdr.ScVal).bytes()).toEqual(
      Buffer.from(
        (await import('@stellaronramp/identity')).splitProof(f.proof.proof).challenge,
      ),
    );
  });

  it.each([
    ['issuerId', 'ZZNOTHEX'],
    ['nonceHex', 'short'],
    ['claimsBitmap', -1],
    ['revocationIndex', 4_294_967_296],
    ['expiresAt', 0],
    ['ledgerExpiry', 1.5],
  ] as const)('fails closed on a malformed %s BEFORE any chain is touched', async (field, bad) => {
    // attestBbsArgs is SYNCHRONOUS: resolve the (awaited) malformed input first, then assert the
    // sync throw — an async wrapper would swallow it into a rejected promise.
    const malformed = await input({ [field]: bad } as Partial<AttestBbsArgsInput>);
    expect(() => attestBbsArgs(malformed)).toThrow(AttestError);
  });

  it('pins the expiresAt REJECTION REASON — the wording must not silently regress', async () => {
    // because nothing asserted reason text. The wording teaches the LEDGER-unit contract
    // (lib.rs:1081-1087); pin both halves — right units present, wrong units absent.
    const malformed = await input({ expiresAt: 0 } as Partial<AttestBbsArgsInput>);
    expect(() => attestBbsArgs(malformed)).toThrow(/u32 ledger sequence/);
    expect(() => attestBbsArgs(malformed)).not.toThrow(/unix/);
  });
});
