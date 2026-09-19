/**
 * Credential custody round-trips. The salt is the load-bearing field: losing it makes the
 * credential unverifiable forever (schema.ts:176-178), so the store enforces its width and
 * deep-copies on BOTH sides — a caller who mutates a buffer after put() must not corrupt what
 * get() hands back.
 */

import { describe, expect, it } from 'vitest';

import {
  InMemoryCredentialStore,
  StoreError,
  type StoredCredential,
} from '../src/index.js';

import { computeSubjectBinding } from '@stellaronramp/identity';

const WALLET_C = 'CAJJ64SHO3R6L6ISWOD2NXACZXMQA6SAUXADCTSHDNLVZQ6Q3O5IVOVW'; // live smoke wallet shape
const WALLET_G = 'GAOS3CYFTRFSBSVN4GORA3PSOIJICMMHDCRRQEOQDS42ASC4V52BXPE3';

function record(overrides: Partial<StoredCredential> = {}): StoredCredential {
  const salt = new Uint8Array(32).fill(9);
  return {
    credential: {
      schemaVersion: '1',
      messages: Array.from({ length: 12 }, (_, i) => `claim${String(i)}=1`),
      signature: new Uint8Array(80),
      issuerPublicKey: new Uint8Array(96),
      claims: {},
    } as unknown as StoredCredential['credential'],
    subjectBindingSalt: salt,
    walletAddress: WALLET_C,
    storedAt: 1_755_000_000,
    ...overrides,
  };
}

describe('InMemoryCredentialStore', () => {
  it('round-trips a record including the salt', async () => {
    const store = new InMemoryCredentialStore();
    await store.put(record());
    const got = await store.get(WALLET_C);
    expect(got).not.toBeNull();
    expect(got?.subjectBindingSalt).toEqual(new Uint8Array(32).fill(9));
    expect(got?.walletAddress).toBe(WALLET_C);
    expect(got?.credential.schemaVersion).toBe('1');
  });

  it('a miss is null, never a throw', async () => {
    const store = new InMemoryCredentialStore();
    await expect(store.get(WALLET_G)).resolves.toBeNull();
  });

  it('mutating the buffer AFTER put does not corrupt the stored salt', async () => {
    const store = new InMemoryCredentialStore();
    const rec = record();
    await store.put(rec);
    rec.subjectBindingSalt.fill(0); // attacker-shaped mutation of the caller's alias
    const got = await store.get(WALLET_C);
    expect(got?.subjectBindingSalt).toEqual(new Uint8Array(32).fill(9));
  });

  it('mutating the buffer returned by get does not corrupt the store', async () => {
    const store = new InMemoryCredentialStore();
    await store.put(record());
    const first = await store.get(WALLET_C);
    first?.subjectBindingSalt.fill(1);
    const second = await store.get(WALLET_C);
    expect(second?.subjectBindingSalt).toEqual(new Uint8Array(32).fill(9));
  });

  it('refuses a wrong-width salt — a record persisted without 32 bytes could never verify', async () => {
    const store = new InMemoryCredentialStore();
    await expect(store.put(record({ subjectBindingSalt: new Uint8Array(16) }))).rejects.toThrow(
      StoreError,
    );
    await expect(store.put(record({ subjectBindingSalt: new Uint8Array(0) }))).rejects.toThrow(
      StoreError,
    );
  });

  it('refuses a non-strkey wallet address', async () => {
    const store = new InMemoryCredentialStore();
    await expect(store.put(record({ walletAddress: 'not-an-address' }))).rejects.toThrow(StoreError);
    // Wrong length: the regex gate catches this class. (Right-shape-wrong-checksum is NOT caught
    // by any regex — checksums need decoding; the store's check is a first gate, not the last.)
    await expect(
      store.put(record({ walletAddress: 'CAJJ64SHO3R6L6ISWOD2NXACZXMQA6SAUXADCTSHDNLVZQ6Q3O5IVO' })),
    ).rejects.toThrow(StoreError); // 54 chars after C — one short
    await expect(
      store.put(record({ walletAddress: 'DAJJ64SHO3R6L6ISWOD2NXACZXMQA6SAUXADCTSHDNLVZQ6Q3O5IVOVW' })),
    ).rejects.toThrow(StoreError); // wrong leading letter
  });

  it('delete returns whether something existed; list is stable', async () => {
    const store = new InMemoryCredentialStore();
    await store.put(record());
    await store.put(record({ walletAddress: WALLET_G }));
    expect(store.size()).toBe(2);
    await expect(store.delete(WALLET_C)).resolves.toBe(true);
    await expect(store.delete(WALLET_C)).resolves.toBe(false);
    const listed = await store.list();
    expect(listed.map((r) => r.walletAddress)).toEqual([WALLET_G]);
  });

  it('the stored salt still derives the SAME subject binding the credential committed to', async () => {
    // The end-to-end reason the store exists: custody today must permit verification later.
    const store = new InMemoryCredentialStore();
    const salt = new Uint8Array(32).fill(7);
    await store.put(record({ subjectBindingSalt: salt }));
    const got = await store.get(WALLET_C);
    const binding = computeSubjectBinding(WALLET_C, got!.subjectBindingSalt);
    const direct = computeSubjectBinding(WALLET_C, salt);
    expect(binding).toBe(direct);
    expect(binding).toMatch(/^[0-9a-f]{64}$/);
  });
});
