/**
 * Holder-side credential custody.
 *
 * A `Credential` is useless without two things that live OUTSIDE it: the 32-byte
 * `subject_binding_salt` (`packages/identity/src/schema.ts:176-178`) and the wallet address it
 * was bound to. The salt is the only input to `computeSubjectBinding(walletAddress, salt)` that
 * the holder supplies — lose it and NOBODY can re-derive or verify the subject binding again;
 * the credential degrades from "selective disclosure bound to my wallet" to "an unattributable
 * signature". The gateway does not retain a copy (it returns the salt in the issue response and
 * forgets it, `apps/gateway-http/src/handlers/issue.ts:80-85`). So the STORE, not the caller,
 * is what makes verification possible later, and this interface refuses to persist a record
 * without one.
 *
 * The browser adapter would implement {@link CredentialStore} over IndexedDB exactly as
 * `InMemoryCredentialStore` implements it — same records, same copy-on-write rules — plus an
 * upgrade hook for schema changes. It is deliberately NOT shipped as dead code: an adapter
 * nothing has ever executed is worse than an interface with zero implementations, because the
 * first browser consumer writes it against REAL storage and finds out then. What this module
 * DOES guarantee is that the in-memory reference implementation encodes every rule the browser
 * one must copy (deep copies on write AND read; key = wallet address; salt width enforced).
 */

import { SUBJECT_BINDING_SALT_BYTES } from '@stellaronramp/identity';
import type { Credential } from '@stellaronramp/identity';

export class StoreError extends Error {
  override readonly name = 'StoreError';
}

const STRKEY_ANY_RE = /^[GC][A-Z2-7]{55}$/;

/** One holder's custody record. Everything needed to derive future proofs, nothing else. */
export interface StoredCredential {
  readonly credential: Credential;
  /**
   * The 32-byte `subject_binding_salt` issued WITH this credential. Persisted beside it because
   * losing it makes the credential unverifiable forever (see module docblock).
   */
  readonly subjectBindingSalt: Uint8Array;
  /** The wallet address (G- or C-strkey) the credential's subject binding commits to. */
  readonly walletAddress: string;
  /** Unix seconds at custody time. Informational; sorting and audit only. */
  readonly storedAt: number;
}

/**
 * The storage seam. All methods async so a durable implementation (IndexedDB, react-native
 * storage, a vault) can slot in without changing callers.
 */
export interface CredentialStore {
  put(record: StoredCredential): Promise<void>;
  /** The record for `walletAddress`, or `null`. Never throws for a miss. */
  get(walletAddress: string): Promise<StoredCredential | null>;
  /** True iff something was deleted. */
  delete(walletAddress: string): Promise<boolean>;
  list(): Promise<readonly StoredCredential[]>;
}

function cloneBytes(b: Uint8Array): Uint8Array {
  return b.slice();
}

/**
 * Deep-copy a record on the way IN and the way OUT. Not paranoia: `Uint8Array`s are aliased, and
 * a store that keeps the caller's buffer hands every later reader whatever the caller mutates
 * into it afterwards — including a tampered salt, which would flip `computeSubjectBinding` to a
 * value the credential never committed to. Copy on both sides and the store is a boundary.
 */
function normalizeRecord(record: StoredCredential): StoredCredential {
  if (!STRKEY_ANY_RE.test(record.walletAddress)) {
    throw new StoreError(`walletAddress "${record.walletAddress}" is not a Stellar G-/C-strkey`);
  }
  if (!(record.subjectBindingSalt instanceof Uint8Array)) {
    throw new StoreError('subjectBindingSalt must be a Uint8Array');
  }
  if (record.subjectBindingSalt.length !== SUBJECT_BINDING_SALT_BYTES) {
    throw new StoreError(
      `subjectBindingSalt must be ${SUBJECT_BINDING_SALT_BYTES} bytes ` +
        `(schema.ts::SUBJECT_BINDING_SALT_BYTES), got ${record.subjectBindingSalt.length} — a ` +
        'record persisted with a wrong-width salt could never be verified',
    );
  }
  if (record.credential === undefined || record.credential === null) {
    throw new StoreError('a stored record without a credential is not a record');
  }
  return {
    ...record,
    subjectBindingSalt: cloneBytes(record.subjectBindingSalt),
    storedAt: record.storedAt,
  };
}

/** The reference implementation. Process-lifetime only: everything dies with the process. */
export class InMemoryCredentialStore implements CredentialStore {
  readonly #records: Map<string, StoredCredential> = new Map();

  async put(record: StoredCredential): Promise<void> {
    const normalized = normalizeRecord(record);
    this.#records.set(normalized.walletAddress, normalized);
  }

  async get(walletAddress: string): Promise<StoredCredential | null> {
    const found = this.#records.get(walletAddress);
    if (found === undefined) return null;
    return { ...found, subjectBindingSalt: cloneBytes(found.subjectBindingSalt) };
  }

  async delete(walletAddress: string): Promise<boolean> {
    return this.#records.delete(walletAddress);
  }

  async list(): Promise<readonly StoredCredential[]> {
    return [...this.#records.values()].map((r) => ({
      ...r,
      subjectBindingSalt: cloneBytes(r.subjectBindingSalt),
    }));
  }

  size(): number {
    return this.#records.size;
  }
}
