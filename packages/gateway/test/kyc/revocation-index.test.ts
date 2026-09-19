/**
 * K4's allocator. A duplicate index makes two credentials share ONE revocation bit, so revoking one
 * silently revokes the other — and, worse in the other direction, reinstating one un-revokes the
 * other. It leaves no trace: both credentials verify, both are individually plausible, and the only
 * evidence is a row in a table nobody is diffing.
 *
 * The brief asked for "a test that hammers it for duplicates". There are three, at 1,000, 10,000 and
 * 50,000 concurrent calls.
 */

import { MINIMUM_STATUS_LIST_ENTRIES } from '@stellaronramp/identity';
import { describe, expect, it } from 'vitest';

import {
  InMemoryRevocationIndexAllocator,
  MAX_REVOCATION_INDEX,
  MINIMUM_LIST_CAPACITY,
  RevocationIndexError,
  assertUsableRevocationIndex,
} from '../../src/kyc/revocation-index.js';
import type { RevocationIndexAllocator } from '../../src/kyc/revocation-index.js';

describe('NO DUPLICATES, under concurrency, hammered', () => {
  it.each([1_000, 10_000, 50_000])(
    '%s CONCURRENT allocate() calls produce zero duplicates',
    async (count) => {
      const allocator = new InMemoryRevocationIndexAllocator();
      const values = await Promise.all(Array.from({ length: count }, () => allocator.allocate()));
      expect(new Set(values).size, 'a duplicate index shares one revocation bit').toBe(count);
      // And the set is exactly [0, count) — monotonic with no gaps.
      expect(Math.min(...values)).toBe(0);
      expect(Math.max(...values)).toBe(count - 1);
    },
  );

  it('produces no duplicates when many INTERLEAVED callers each allocate several', async () => {
    const allocator = new InMemoryRevocationIndexAllocator();
    const batches = await Promise.all(
      Array.from({ length: 200 }, async () => {
        const mine: number[] = [];
        for (let i = 0; i < 20; i += 1) mine.push(await allocator.allocate());
        return mine;
      }),
    );
    const all = batches.flat();
    expect(all).toHaveLength(4_000);
    expect(new Set(all).size).toBe(4_000);
  });

  it('is strictly monotonic in sequential use', async () => {
    const allocator = new InMemoryRevocationIndexAllocator();
    let previous = -1;
    for (let i = 0; i < 500; i += 1) {
      const next = await allocator.allocate();
      expect(next).toBeGreaterThan(previous);
      previous = next;
    }
  });

  it('has ONE method that both reserves and returns — no peek/next pair to race on', () => {
    const allocator = new InMemoryRevocationIndexAllocator();
    const proto = Object.getPrototypeOf(allocator) as Record<string, unknown>;
    expect(typeof allocator.allocate).toBe('function');
    // `next` is a diagnostic getter, not a reservation-free allocation path.
    expect(typeof proto['peek']).toBe('undefined');
    expect(typeof proto['reserve']).toBe('undefined');
  });
});

describe('NEVER REUSES an index, even a "free" one', () => {
  /**
   * Reuse is tempting — a revoked credential's index is "free" once the credential has expired — and
   * it is wrong: the status list is a PUBLIC DOCUMENT WITH A HISTORY, so re-issuing index N to a second
   * person means anyone who cached yesterday's list reads the FIRST person's revocation state for the
   * SECOND person.
   */
  it('refuses to WRAP when the space is exhausted, rather than reusing index 0', async () => {
    const allocator = new InMemoryRevocationIndexAllocator({ start: 10, max: 12 });
    expect(await allocator.allocate()).toBe(10);
    expect(await allocator.allocate()).toBe(11);
    expect(await allocator.allocate()).toBe(12);
    await expect(allocator.allocate()).rejects.toThrow(/exhausted|refusing to wrap/);
    // And it stays exhausted; it does not recover into a reuse.
    await expect(allocator.allocate()).rejects.toThrow(RevocationIndexError);
  });

  it('says WHY reuse is refused, so nobody "optimises" it back in', async () => {
    const allocator = new InMemoryRevocationIndexAllocator({ start: 0, max: 0 });
    await allocator.allocate();
    let caught: Error | undefined;
    try {
      await allocator.allocate();
    } catch (e) {
      caught = e as Error;
    }
    expect(caught?.message).toMatch(/cached copy of the status list|previous holder/);
  });

  /**
   * RESUMPTION, not restart. A real deployment restoring this from a database resumes; an allocator
   * that silently restarts at 0 after a process restart IS the duplicate-index bug with extra steps.
   */
  it('resumes from a supplied start, so a process restart does not re-issue index 0', async () => {
    const first = new InMemoryRevocationIndexAllocator();
    const issued = await Promise.all([first.allocate(), first.allocate(), first.allocate()]);
    expect(issued).toEqual([0, 1, 2]);
    // "Restart", restoring from the persisted high-water mark.
    const resumed = new InMemoryRevocationIndexAllocator({ start: first.next });
    expect(await resumed.allocate()).toBe(3);
    expect(issued).not.toContain(3);
  });

  it('exposes the high-water mark so a deployment CAN persist and resume it', async () => {
    const allocator = new InMemoryRevocationIndexAllocator({ start: 100 });
    expect(allocator.next).toBe(100);
    await allocator.allocate();
    expect(allocator.next).toBe(101);
  });
});

describe('the bounds are the ON-CHAIN u32, not the status list', () => {
  it('caps at 2^32-1, because the attestation payload encodes revocation_index as a u32', () => {
    expect(MAX_REVOCATION_INDEX).toBe(0xffff_ffff);
    expect(MAX_REVOCATION_INDEX).toBe(4_294_967_295);
  });

  it('reports identity\'s spec-minimum list capacity rather than inventing one', () => {
    expect(MINIMUM_LIST_CAPACITY).toBe(MINIMUM_STATUS_LIST_ENTRIES);
    expect(MINIMUM_LIST_CAPACITY).toBe(131_072);
  });

  it.each([
    ['a negative start', { start: -1 }],
    ['a non-integer start', { start: 1.5 }],
    ['a start above the u32 cap', { start: 0x1_0000_0000 }],
    ['a NaN start', { start: Number.NaN }],
    ['a max below the start', { start: 100, max: 99 }],
    ['a max above the u32 cap', { max: 0x1_0000_0000 }],
    ['a non-integer max', { max: 1.5 }],
  ])('refuses %s at construction', (_label, options) => {
    expect(() => new InMemoryRevocationIndexAllocator(options)).toThrow(RevocationIndexError);
  });

  it('accepts the exact boundaries', () => {
    expect(() => new InMemoryRevocationIndexAllocator({ start: 0 })).not.toThrow();
    expect(
      () => new InMemoryRevocationIndexAllocator({ start: MAX_REVOCATION_INDEX }),
    ).not.toThrow();
  });
});

describe('an index from ANYWHERE ELSE is guarded before a signature is spent on it', () => {
  it('accepts a valid index and returns it', () => {
    expect(assertUsableRevocationIndex(0)).toBe(0);
    expect(assertUsableRevocationIndex(4242)).toBe(4242);
    expect(assertUsableRevocationIndex(MAX_REVOCATION_INDEX)).toBe(MAX_REVOCATION_INDEX);
  });

  it.each([
    ['a negative number', -1],
    ['a float', 1.5],
    ['NaN', Number.NaN],
    ['Infinity', Number.POSITIVE_INFINITY],
    ['above the u32 cap', 0x1_0000_0000],
    ['a numeric string', '4242'],
    ['null', null],
    ['undefined', undefined],
    ['a bigint', 1n],
    ['an object', {}],
    ['an array', [4242]],
    ['a boolean', true],
  ])('refuses %s, because the payload encodes it as a u32', (_label, value) => {
    expect(() => assertUsableRevocationIndex(value)).toThrow(RevocationIndexError);
  });
});

describe('the interface documents a production shape, so the real one is a drop-in', () => {
  it('a five-line custom allocator satisfies the interface', async () => {
    // The proof the seam is real: a second implementation, and it is trivial.
    let n = 900;
    const custom: RevocationIndexAllocator = { allocate: async () => n++ };
    expect(await custom.allocate()).toBe(900);
    expect(await custom.allocate()).toBe(901);
  });

  it('names the Postgres SEQUENCE and the Redis INCR forms, and warns off SELECT max(idx)+1', async () => {
    const source = await import('node:fs/promises').then((fs) =>
      fs.readFile(new URL('../../src/kyc/revocation-index.ts', import.meta.url), 'utf8'),
    );
    expect(source).toContain("nextval('revocation_index_seq')");
    expect(source).toContain('INCR statuslist:');
    // The anti-pattern must be named, not merely omitted: SELECT max(idx)+1 is a lost-update race.
    expect(source).toContain('SELECT max(idx)+1');
    expect(source).toContain('lost-update race');
  });

  it('documents that the in-memory one is NOT a production control, and why', async () => {
    const source = await import('node:fs/promises').then((fs) =>
      fs.readFile(new URL('../../src/kyc/revocation-index.ts', import.meta.url), 'utf8'),
    );
    expect(source).toContain('NOT A PRODUCTION CONTROL');
    expect(source).toContain('two replicas start at the same');
  });
});
