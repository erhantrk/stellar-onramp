/**
 * Revocation-index allocation.
 *
 * Every credential needs a UNIQUE W3C Bitstring Status List position. An allocator that hands out a
 * duplicate index makes two credentials share one revocation bit, so revoking one silently revokes
 * the other — and, far worse in the other direction, REINSTATING one un-revokes the other. That is a
 * compliance failure that leaves no trace: both credentials verify, both are individually plausible,
 * and the only evidence is a row in a table nobody is diffing.
 *
 * This is the same class of bug as a reused nonce, and it is defended the same way: allocation is a
 * SINGLE atomic operation with no read-then-write, and the in-memory implementation is documented as
 * NOT a production control.
 *
 * THE INDEX IS ALSO SIGNED ON CHAIN. The chain track's `LaneBChainSigner.signAttestation` takes
 * `revocationIndex` and puts it in the .v2 attestation payload, where it is stored in the
 * `ClaimRecord` and is the audit link from an on-chain attestation back to a status-list bit. The
 * contract never READS it, so a duplicate is not caught there either.
 */

import { MINIMUM_STATUS_LIST_ENTRIES } from '@stellaronramp/identity';

export class RevocationIndexError extends Error {
  override readonly name = 'RevocationIndexError';
}

/**
 * The allocator.
 *
 * ONE METHOD, and it both reserves and returns — there is no `peek`/`next` pair, for exactly the
 * reason `WebhookDedupeStore` has no `has()`: a check-then-act split invites two concurrent issuances
 * to observe the same free index.
 *
 * PRODUCTION SHAPE, so the real one is a drop-in:
 *
 *   Postgres:  INSERT INTO revocation_index (idx, issuer_id, allocated_at)
 *              VALUES (nextval('revocation_index_seq'), $1, $2) RETURNING idx;
 *              -- a SEQUENCE, not `SELECT max(idx)+1`. The latter is a lost-update race under any
 *              -- isolation level below SERIALIZABLE, and under SERIALIZABLE it is a serialisation
 *              -- failure storm at issuance rate.
 *   Redis:     INCR statuslist:{issuerId}:next     -- atomic, monotonic, survives concurrency
 *
 * BOTH ARE MONOTONIC AND NEITHER REUSES. Reuse is tempting — a revoked credential's index is "free"
 * once the credential has expired — and it is wrong: the status list is a public document with a
 * history, and re-issuing index N to a second person means anyone who cached yesterday's list reads
 * the FIRST person's revocation state for the SECOND person. Indexes are cheap (the spec's minimum
 * list is 131,072 entries and a list can be much larger); a person's revocation history is not.
 */
export interface RevocationIndexAllocator {
  /** Atomically reserve and return the next unused index. Never returns the same value twice. */
  allocate(): Promise<number>;
}

/**
 * The largest index this system will allocate.
 *
 * Bounded by the on-chain field, not by the status list: the attestation payload encodes
 * `revocation_index` as a u32 (see `u32be` in src/chain/payload.ts), so an index above 2^32-1 cannot
 * be attested at all. The status list itself would happily hold more.
 *
 * A 2^32-entry uncompressed bitstring is 512 MiB, which is far past identity's
 * `MAX_STATUS_LIST_BYTES` (16 MiB, i.e. 134,217,728 entries) — so in practice the STATUS LIST runs
 * out three orders of magnitude before the u32 does, and a real deployment shards into multiple
 * lists long before either. That sharding is not built here: it needs a list id in the credential,
 * version bump and reissuance). Recorded as a real, dated limit rather than discovered at 134 M
 * credentials.
 */
export const MAX_REVOCATION_INDEX = 0xffff_ffff;

/**
 * Largest index that fits inside a single spec-minimum status list. Above this the publisher must be
 * told a larger `entries` count, which it supports.
 */
export const MINIMUM_LIST_CAPACITY = MINIMUM_STATUS_LIST_ENTRIES;

/**
 * Process-local, monotonic allocator.
 *
 * NOT A PRODUCTION CONTROL, and the failure is not subtle: two replicas start at the same `start`
 * value and issue the same indexes to different people. Use the Postgres sequence or the Redis INCR
 * above. This exists so tests and a single-process dev gateway work, and so the INTERFACE has a
 * second implementation.
 *
 * `start` is a parameter because a real deployment restoring this from a database resumes rather than
 * restarts, and an allocator that silently restarts at 0 after a process restart is the duplicate-index
 * bug with extra steps.
 */
export class InMemoryRevocationIndexAllocator implements RevocationIndexAllocator {
  #next: number;
  readonly #max: number;

  constructor(options: { start?: number; max?: number } = {}) {
    const start = options.start ?? 0;
    const max = options.max ?? MAX_REVOCATION_INDEX;
    if (!Number.isInteger(start) || start < 0 || start > MAX_REVOCATION_INDEX) {
      throw new RevocationIndexError(
        `refusing a revocation-index allocator starting at ${String(start)}; it must be an integer ` +
          `in [0, ${MAX_REVOCATION_INDEX}]`,
      );
    }
    if (!Number.isInteger(max) || max < start || max > MAX_REVOCATION_INDEX) {
      throw new RevocationIndexError(
        `refusing a revocation-index allocator capped at ${String(max)}; the cap must be an integer ` +
          `in [start, ${MAX_REVOCATION_INDEX}]`,
      );
    }
    this.#next = start;
    this.#max = max;
  }

  /**
   * `allocate` is async to match the interface (a real one is a database round trip) but the
   * increment itself is synchronous and therefore atomic with respect to the JavaScript event loop:
   * there is no `await` between reading `#next` and writing it. That is what makes the concurrency
   * test — 10,000 concurrent `allocate()` calls, zero duplicates — pass rather than pass by luck.
   * Putting an `await` in the middle of this method would break it, which is why the read and the
   * write are adjacent and this comment says so.
   */
  async allocate(): Promise<number> {
    const value = this.#next;
    if (value > this.#max) {
      throw new RevocationIndexError(
        `revocation index space exhausted at ${this.#max}; refusing to wrap. Reusing an index would ` +
          "make a new credential inherit the previous holder's revocation state in every cached " +
          'copy of the status list',
      );
    }
    this.#next = value + 1;
    return value;
  }

  /** Test/diagnostic only: the next value that would be handed out. */
  get next(): number {
    return this.#next;
  }
}

/**
 * Guard for an index that arrived from somewhere other than our allocator — a database row, a config
 * file, a replayed issuance. Cheap, and it fires before a signature is spent on it.
 */
export function assertUsableRevocationIndex(value: unknown): number {
  if (!Number.isInteger(value) || (value as number) < 0 || (value as number) > MAX_REVOCATION_INDEX) {
    throw new RevocationIndexError(
      `refusing revocation index ${String(value)}; it must be an integer in ` +
        `[0, ${MAX_REVOCATION_INDEX}] because the attestation payload encodes it as a u32`,
    );
  }
  return value as number;
}
