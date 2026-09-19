/**
 * registry.ts against a SCRIPTED submitter — no chain, no network.
 *
 * its two load-bearing guards decorative — collapsing #3-only discrimination to "every failure
 * is issuerNotFound:true" turned nothing red, and neither did deleting findSubstituteIssuer's
 * flag-byte gate. These tests exist to make both mutations RED:
 *   - #3-only discrimination: a non-#3 contract error must NOT be reported as a missing issuer
 *     (the whole point is refusing to hand the operator a `register_issuer` command that fixes
 *     an RPC failure);
 *   - the flag-byte gate `(key[0] & 0xe0) === 0`: a substitute whose key carries a set flag bit
 *     is unusable (#6 at lib.rs:1148-1173) and must be stepped past, not returned.
 */

import { describe, expect, it } from 'vitest';

import { decompressG2, generateIssuerKeyPair } from '@stellaronramp/identity';
import { bytesToHex } from '@noble/hashes/utils.js';

import {
  IssuerPreflightError,
  assertIssuerActive,
  findSubstituteIssuer,
} from '../../src/index.js';

/** Contract errors as the gateway decoder sees them: `Error(Contract, #N)` message text. */
const contractError = (n: number): Error =>
  Object.assign(new Error(`Error(Contract, #${n})`), {});

const REGISTRY = 'CAAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQC526';
const ID_SELF = 'aa'.repeat(32);
const ID_TOMBSTONE = 'bb'.repeat(32);
const ID_USABLE = 'cc'.repeat(32);

/** A synthetic 192-byte "stored key" whose flag byte is clear — findSubstituteIssuer only
 *  inspects byte 0 here, so the rest is filler (the cross-check against the LOCAL key lives in
 *  assertIssuerActive, tested separately with a real keypair). */
const usableKey = (): Uint8Array => Uint8Array.from({ length: 192 }, (_, i) => (i + 1) & 0xff);

describe('assertIssuerActive — #3-ONLY discrimination', () => {
  it('returns the registry key hex when active_key matches the LOCAL key', async () => {
    const { publicKey } = await generateIssuerKeyPair();
    const stored = decompressG2(publicKey);
    const seen: string[] = [];
    const result = await assertIssuerActive(
      { simulateRead: async (_op: unknown, label: string) => (seen.push(label), stored) } as never,
      REGISTRY,
      ID_SELF,
      publicKey,
    );
    expect(result).toBe(bytesToHex(stored));
    expect(seen).toEqual(['active_key']);
  });

  it('reports contract error #3 as issuerNotFound:true — the one case register_issuer fixes', async () => {
    const { publicKey } = await generateIssuerKeyPair();
    const cause = contractError(3);
    const promise = assertIssuerActive(
      { simulateRead: async () => Promise.reject(cause) } as never,
      REGISTRY,
      ID_SELF,
      publicKey,
    );
    await expect(promise).rejects.toBeInstanceOf(IssuerPreflightError);
    const caught = (await promise.catch((e: IssuerPreflightError) => e)) as IssuerPreflightError;
    expect(caught.issuerNotFound).toBe(true);
    expect(caught.cause).toBe(cause);
    expect(caught.message).toMatch(/IssuerNotFound/);
  });

  it('reports ANY other contract error as issuerNotFound:false — registering would fix nothing', async () => {
    const { publicKey } = await generateIssuerKeyPair();
    // #7 is kyc-gate's UntrustedIssuer; on the REGISTRY surface an unexpected code means the
    // read itself went wrong (wrong contract, wrong RPC) and must not masquerade as #3.
    const promise = assertIssuerActive(
      { simulateRead: async () => Promise.reject(contractError(7)) } as never,
      REGISTRY,
      ID_SELF,
      publicKey,
    );
    const caught = (await promise.catch((e: IssuerPreflightError) => e)) as IssuerPreflightError;
    expect(caught).toBeInstanceOf(IssuerPreflightError);
    expect(caught.issuerNotFound).toBe(false);
    expect(caught.message).toMatch(/NOT/);
  });

  it('refuses a registry key that differs from the LOCAL key — the unreadable-pairing trap', async () => {
    const { publicKey } = await generateIssuerKeyPair();
    const wrong = usableKey(); // right shape, different point
    const caught = (await assertIssuerActive(
      { simulateRead: async () => wrong } as never,
      REGISTRY,
      ID_SELF,
      publicKey,
    ).catch((e: IssuerPreflightError) => e)) as IssuerPreflightError;
    expect(caught).toBeInstanceOf(IssuerPreflightError);
    expect(caught.message).toMatch(/DIFFERENT key/);
    expect(caught.issuerNotFound).toBe(false);
  });
});

describe('findSubstituteIssuer — flag-byte gate and tombstone walk', () => {
  it('steps over the excluded id and #3 tombstones, returning the first usable issuer', async () => {
    // Keyed per candidate by peeking the op: the fake decodes nothing — instead the test keys
    // replies by call ORDER, which is the module's own walk order.
    const replies: Array<() => Promise<Uint8Array>> = [
      async () => Promise.reject(contractError(3)), // ID_TOMBSTONE: revoked, left in the inventory
      async () => usableKey(), // ID_USABLE
    ];
    let i = 0;
    const submitter = {
      simulateRead: async (_op: unknown, label: string) => {
        if (label === 'issuer_ids') return [Buffer.from(ID_SELF, 'hex'), Buffer.from(ID_TOMBSTONE, 'hex'), Buffer.from(ID_USABLE, 'hex')];
        if (label.startsWith('active_key')) return replies[i++]!();
        throw new Error(`unexpected label ${label}`);
      },
    } as never;
    const found = await findSubstituteIssuer(submitter, REGISTRY, ID_SELF);
    expect(found).toBe(ID_USABLE);
  });

  it('steps past a usable-id whose KEY carries a set flag byte (#6 downstream)', async () => {
    const badFlag = usableKey();
    badFlag[0] = 0xff; // (0xff & 0xe0) !== 0 — the gate must skip this candidate
    const replies: Array<() => Promise<Uint8Array>> = [
      async () => badFlag, // ID_TOMBSTONE slot: alive but unusable key
      async () => usableKey(), // ID_USABLE
    ];
    let i = 0;
    const submitter = {
      simulateRead: async (_op: unknown, label: string) => {
        if (label === 'issuer_ids') return [Buffer.from(ID_TOMBSTONE, 'hex'), Buffer.from(ID_USABLE, 'hex')];
        if (label.startsWith('active_key')) return replies[i++]!();
        throw new Error(`unexpected label ${label}`);
      },
    } as never;
    expect(await findSubstituteIssuer(submitter, REGISTRY, ID_SELF)).toBe(ID_USABLE);
  });

  it('returns null when every non-excluded issuer is a tombstone — and SAYS so', async () => {
    const submitter = {
      simulateRead: async (_op: unknown, label: string) => {
        if (label === 'issuer_ids') return [Buffer.from(ID_SELF, 'hex'), Buffer.from(ID_TOMBSTONE, 'hex')];
        if (label.startsWith('active_key')) return Promise.reject(contractError(3));
        throw new Error(`unexpected label ${label}`);
      },
    } as never;
    expect(await findSubstituteIssuer(submitter, REGISTRY, ID_SELF)).toBeNull();
  });

  it('RETHROWS a non-#3 failure — a transport error is not "no substitute available"', async () => {
    const transport = new Error('simulated RPC timeout');
    const submitter = {
      simulateRead: async (_op: unknown, label: string) => {
        if (label === 'issuer_ids') return [Buffer.from(ID_TOMBSTONE, 'hex')];
        if (label.startsWith('active_key')) return Promise.reject(transport);
        throw new Error(`unexpected label ${label}`);
      },
    } as never;
    await expect(findSubstituteIssuer(submitter, REGISTRY, ID_SELF)).rejects.toBe(transport);
  });
});
