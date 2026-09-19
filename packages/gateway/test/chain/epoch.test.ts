/**
 * THE EPOCH READER, and the discrimination that is the whole point of it.
 *
 * `NoClaimRecord` (#3) means epoch 0. NOTHING ELSE DOES. Each of the "nothing else" shapes is driven
 * through the reader individually below, because a `try { … } catch { return 0 }` passes every test
 * that only checks the happy path and the #3 path.
 *
 * ZERO NETWORK. Every case runs against a fake `GateSimulator`.
 */

import { describe, expect, it } from 'vitest';

import {
  EpochReadError,
  decodeClaimRecord,
  readRevocationEpoch,
  readSubjectChainState,
} from '../../src/chain/epoch.js';
import {
  LIVE_NO_CLAIM_RECORD_ERROR,
  TEST_SUBJECT,
  contractError,
  rawClaimRecord,
  rejectingSimulator,
  resolvingSimulator,
} from './fakes.js';

const CONTRACT_SUBJECT = 'CABAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAFNSZ';

describe('the happy path returns the WHOLE record, not just the epoch', () => {
  it('decodes every field', async () => {
    const state = await readSubjectChainState(
      resolvingSimulator(rawClaimRecord({ revocation_epoch: 3 })),
      TEST_SUBJECT,
    );
    expect(state.subject).toBe(TEST_SUBJECT);
    expect(state.revocationEpoch).toBe(3);
    expect(state.revoked).toBe(false);
    expect(state.record).not.toBeNull();
    expect(state.record?.claims).toBe(5);
    expect(state.record?.expiresAt).toBe(4_289_411);
    expect(state.record?.issuedAt).toBe(4_189_413);
    expect(state.record?.revocationIndex).toBe(4711);
    expect(state.record?.issuerId.length).toBe(32);
  });

  it('reports a revocation tombstone as revoked — claims 0 is a tombstone, not an attestation', async () => {
    const state = await readSubjectChainState(
      resolvingSimulator(rawClaimRecord({ claims: 0, revocation_epoch: 1 })),
      TEST_SUBJECT,
    );
    expect(state.revoked).toBe(true);
    expect(state.revocationEpoch).toBe(1);
  });

  it('works for a contract-address subject as well as an account one', async () => {
    const state = await readSubjectChainState(resolvingSimulator(rawClaimRecord()), CONTRACT_SUBJECT);
    expect(state.subject).toBe(CONTRACT_SUBJECT);
  });

  it('readRevocationEpoch is the same read, narrowed', async () => {
    expect(
      await readRevocationEpoch(resolvingSimulator(rawClaimRecord({ revocation_epoch: 9 })), TEST_SUBJECT),
    ).toBe(9);
  });

  it('accepts bigint u32s, which is what scValToNative can hand back', async () => {
    const state = await readSubjectChainState(
      resolvingSimulator(rawClaimRecord({ revocation_epoch: 2n, claims: 5n })),
      TEST_SUBJECT,
    );
    expect(state.revocationEpoch).toBe(2);
    expect(state.record?.claims).toBe(5);
  });
});

describe('NoClaimRecord (#3), and ONLY #3, means epoch 0', () => {
  it('the exact live-testnet error string yields epoch 0 and a null record', async () => {
    const state = await readSubjectChainState(
      rejectingSimulator(new Error(LIVE_NO_CLAIM_RECORD_ERROR)),
      TEST_SUBJECT,
    );
    expect(state.revocationEpoch).toBe(0);
    expect(state.record).toBeNull();
    expect(state.revoked).toBe(false);
  });

  it('a bare `HostError: Error(Contract, #3)` also yields epoch 0', async () => {
    expect(await readRevocationEpoch(rejectingSimulator(contractError(3)), TEST_SUBJECT)).toBe(0);
  });
});

describe('EVERYTHING ELSE THROWS. This is the bug the only existing example used to have.', () => {
  // error, not just NoClaimRecord: a transient RPC failure, a timeout, a wrong contract id, a
  // malformed response and an archived-entry error ALL silently became "epoch 0", and the gateway then
  // signed at an epoch the chain does not agree with. Each shape gets its own case here.
  it.each([
    ['a transport failure', new Error('fetch failed')],
    ['a DNS failure', new Error('getaddrinfo ENOTFOUND soroban-testnet.stellar.org')],
    ['a request timeout', new Error('claim_record(GAOS…) simulation timed out after 15000ms')],
    ['an HTTP 502', new Error('Request failed with status code 502')],
    ['a malformed JSON-RPC response', new SyntaxError('Unexpected token < in JSON at position 0')],
    ['a wrong contract id', new Error('simulation failed: HostError: Error(WasmVm, MissingValue)')],
    ['an archived entry', new Error('Error(Storage, MissingValue): archived entry')],
    ['a NON-#3 contract error (#2 NotInitialized)', contractError(2)],
    ['a NON-#3 contract error (#9 GatewayKeyNotSet)', contractError(9)],
    // The alias trap: a decoder matching `#3` without the closing paren would read NoClaimRecord here.
    ['a contract error whose number STARTS with 3 (#30)', contractError(30)],
    ['a contract error whose number CONTAINS 3 (#13)', contractError(13)],
    ['an ambiguous diagnostic naming two codes', new Error('Error(Contract, #3) then Error(Contract, #5)')],
    ['a thrown string', 'something went wrong'],
    ['a thrown undefined', undefined],
  ])('%s throws EpochReadError and does NOT return 0', async (_label, err) => {
    const sim = rejectingSimulator(err);
    await expect(readSubjectChainState(sim, TEST_SUBJECT)).rejects.toThrow(EpochReadError);
    await expect(readRevocationEpoch(sim, TEST_SUBJECT)).rejects.toThrow(/refusing to assume/);
  });

  it('names the offending contract error so an operator sees which one it was', async () => {
    await expect(readSubjectChainState(rejectingSimulator(contractError(14)), TEST_SUBJECT)).rejects.toThrow(
      /SubjectRevoked/,
    );
  });

  it('keeps the original throw as `cause`, so nothing is lost', async () => {
    const cause = new Error('fetch failed');
    await expect(readSubjectChainState(rejectingSimulator(cause), TEST_SUBJECT)).rejects.toMatchObject({
      name: 'EpochReadError',
      subject: TEST_SUBJECT,
      cause,
    });
  });

  it('a SUCCESSFUL call whose payload does not decode is not epoch 0 either', async () => {
    for (const garbage of [
      null,
      undefined,
      'a string',
      42,
      [],
      rawClaimRecord({ revocation_epoch: undefined }),
      rawClaimRecord({ revocation_epoch: -1 }),
      rawClaimRecord({ revocation_epoch: 'x' }),
      rawClaimRecord({ issuer_id: new Uint8Array(31) }),
      rawClaimRecord({ issuer_id: 'not bytes' }),
      rawClaimRecord({ claims: 0x1_0000_0000 }),
    ]) {
      await expect(readSubjectChainState(resolvingSimulator(garbage), TEST_SUBJECT)).rejects.toThrow(
        EpochReadError,
      );
    }
  });
});

describe('the subject is validated BEFORE an RPC call is spent', () => {
  it('a malformed address throws without calling the simulator', async () => {
    let called = false;
    const sim = {
      async simulateClaimRecord() {
        called = true;
        return rawClaimRecord();
      },
    };
    await expect(readSubjectChainState(sim, 'not-an-address')).rejects.toThrow();
    await expect(readSubjectChainState(sim, '')).rejects.toThrow();
    expect(called).toBe(false);
  });
});

describe('decodeClaimRecord in isolation', () => {
  it('names the field it could not read', () => {
    expect(() => decodeClaimRecord(rawClaimRecord({ expires_at: 'soon' }))).toThrow(
      /claim_record\.expires_at is not a u32/,
    );
    expect(() => decodeClaimRecord(rawClaimRecord({ issuer_id: new Uint8Array(16) }))).toThrow(
      /issuer_id is not 32 bytes/,
    );
    expect(() => decodeClaimRecord(null)).toThrow(/not a record/);
  });

  it('copies issuer_id rather than aliasing the caller’s buffer', () => {
    const raw = rawClaimRecord();
    const decoded = decodeClaimRecord(raw);
    (raw['issuer_id'] as Uint8Array).fill(0xff);
    expect(decoded.issuerId.every((b) => b === 0)).toBe(true);
  });

});
