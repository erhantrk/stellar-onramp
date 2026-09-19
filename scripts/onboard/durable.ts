/**
 * The portal's DURABLE seams — the places where an in-memory stand-in would quietly make the
 * on-chain record, or the published status list, a lie across restarts.
 *
 *   * `JsonFileRevocationIndexAllocator`. The gateway signs a `revocation_index` into every
 *     credential and `attest_bbs` writes it into the ClaimRecord as the audit link back to the
 *     status list. An allocator that restarts at 0 on every boot hands the same index to two
 *     different credentials, and the link is then worthless. This one keeps its counter in a file
 *     and writes it BEFORE returning, so a crash between "allocated" and "used" wastes an index
 *     rather than reusing one.
 *
 *   * `JsonFileCredentialStore`. The gateway keeps no copy of a credential by design, so the
 *     HOLDER must — together with the 32-byte subject-binding salt, without which the credential
 *     is unverifiable forever (packages/sdk/src/store.ts). This implements the SDK's
 *     `CredentialStore` seam over a JSON file so a portal account can re-prove after a restart.
 *
 * All three write atomically (temp file + rename) like `accounts.ts`, and live under the same
 * gitignored `scripts/.demo-data/` directory. Dev-grade: single process, no locking, and the
 * holder store is the SERVER holding the holder's material — a real deployment keeps the
 * credential in the wallet (IndexedDB, a keychain), never on the issuer's side of the fence.
 */

import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';

import { deserializeCredential, serializeCredential } from '@stellaronramp/identity';
import type { SerializedCredential } from '@stellaronramp/identity';
import type { RevocationIndexAllocator } from '@stellaronramp/gateway';
import type { CredentialStore, StoredCredential } from '@stellaronramp/sdk';

/* -------------------------------------------------------------------------- */
/* status list store                                                           */
/* -------------------------------------------------------------------------- */

interface StatusListFile {
  version: 1;
  revoked: number[];
}

/**
 * The set of revoked credential indexes the gateway publishes at `GET /v1/status-list/{issuer}`.
 * Structural match for `apps/gateway-http`'s `StatusListStore` seam (`revokedIndexes()`), kept
 * in a file so a revocation survives a restart. The portal has no revoke button yet; the store is
 * here so the published list is a real, mutable one rather than a constant `[]`.
 */
export class JsonFileStatusListStore {
  readonly #path: string;
  readonly #revoked = new Set<number>();

  constructor(path: string) {
    this.#path = path;
    const raw = readJson(path) as Partial<StatusListFile> | undefined;
    if (raw === undefined) return;
    if (raw.version !== 1 || !Array.isArray(raw.revoked)) {
      throw new Error(`${path} is not a version-1 status-list file; refusing to guess`);
    }
    for (const i of raw.revoked) if (Number.isInteger(i) && i >= 0) this.#revoked.add(i);
  }

  revoke(index: number): void {
    this.#revoked.add(index);
    this.#flush();
  }

  clear(index: number): void {
    if (this.#revoked.delete(index)) this.#flush();
  }

  revokedIndexes(): readonly number[] {
    return [...this.#revoked].sort((a, b) => a - b);
  }

  #flush(): void {
    const file: StatusListFile = { version: 1, revoked: this.revokedIndexes().slice() };
    writeAtomic(this.#path, JSON.stringify(file));
  }
}

/* -------------------------------------------------------------------------- */
/* shared file helpers                                                         */
/* -------------------------------------------------------------------------- */

function writeAtomic(path: string, body: string): void {
  mkdirSync(dirname(path), { recursive: true });
  const tmp = `${path}.${process.pid}.tmp`;
  writeFileSync(tmp, body, { mode: 0o600 });
  renameSync(tmp, path);
}

function readJson(path: string): unknown {
  if (!existsSync(path)) return undefined;
  return JSON.parse(readFileSync(path, 'utf8')) as unknown;
}

/* -------------------------------------------------------------------------- */
/* revocation index allocator                                                  */
/* -------------------------------------------------------------------------- */

interface AllocatorFile {
  version: 1;
  /** The NEXT index to hand out. Every index below it has been allocated at some point. */
  next: number;
}

export class JsonFileRevocationIndexAllocator implements RevocationIndexAllocator {
  readonly #path: string;
  #next: number;
  // Serialises concurrent `allocate()` calls: the counter is read-modify-write and two runs
  // finishing issuance in the same tick must not observe the same `#next`.
  #chain: Promise<void> = Promise.resolve();

  constructor(path: string) {
    this.#path = path;
    const raw = readJson(path) as Partial<AllocatorFile> | undefined;
    if (raw === undefined) {
      this.#next = 0;
    } else if (raw.version === 1 && Number.isInteger(raw.next) && (raw.next as number) >= 0) {
      this.#next = raw.next as number;
    } else {
      throw new Error(`${path} is not a version-1 revocation-index file; refusing to guess`);
    }
  }

  /** The next index that WILL be handed out (for logs and tests). */
  get next(): number {
    return this.#next;
  }

  allocate(): Promise<number> {
    const result = this.#chain.then(() => {
      const index = this.#next;
      this.#next = index + 1;
      // Persist BEFORE the caller sees the index. A crash after the write wastes one index; a
      // crash before it cannot have handed the index to anyone.
      writeAtomic(this.#path, JSON.stringify({ version: 1, next: this.#next } satisfies AllocatorFile));
      return index;
    });
    this.#chain = result.then(
      () => undefined,
      () => undefined,
    );
    return result;
  }
}

/* -------------------------------------------------------------------------- */
/* holder-side credential store                                                */
/* -------------------------------------------------------------------------- */

interface PersistedCredential {
  walletAddress: string;
  credential: SerializedCredential;
  /** 64 hex chars — the 32-byte subject-binding salt. */
  subjectBindingSaltHex: string;
  storedAt: number;
}

interface CredentialFile {
  version: 1;
  credentials: PersistedCredential[];
}

export class JsonFileCredentialStore implements CredentialStore {
  readonly #path: string;
  readonly #records = new Map<string, PersistedCredential>();

  constructor(path: string) {
    this.#path = path;
    const raw = readJson(path) as Partial<CredentialFile> | undefined;
    if (raw === undefined) return;
    if (raw.version !== 1 || !Array.isArray(raw.credentials)) {
      throw new Error(`${path} is not a version-1 credential file; refusing to guess`);
    }
    for (const rec of raw.credentials) this.#records.set(rec.walletAddress, rec);
  }

  get size(): number {
    return this.#records.size;
  }

  #flush(): void {
    const file: CredentialFile = { version: 1, credentials: [...this.#records.values()] };
    writeAtomic(this.#path, JSON.stringify(file, null, 2));
  }

  async put(record: StoredCredential): Promise<void> {
    if (record.subjectBindingSalt.length !== 32) {
      throw new Error(
        `refusing to store a ${record.subjectBindingSalt.length}-byte subject-binding salt; the ` +
          'credential could never be verified against it',
      );
    }
    this.#records.set(record.walletAddress, {
      walletAddress: record.walletAddress,
      credential: serializeCredential(record.credential),
      subjectBindingSaltHex: Buffer.from(record.subjectBindingSalt).toString('hex'),
      storedAt: record.storedAt,
    });
    this.#flush();
  }

  async get(walletAddress: string): Promise<StoredCredential | null> {
    const rec = this.#records.get(walletAddress);
    return rec === undefined ? null : toStored(rec);
  }

  async delete(walletAddress: string): Promise<boolean> {
    const had = this.#records.delete(walletAddress);
    if (had) this.#flush();
    return had;
  }

  async list(): Promise<readonly StoredCredential[]> {
    return [...this.#records.values()].map(toStored);
  }
}

function toStored(rec: PersistedCredential): StoredCredential {
  return {
    credential: deserializeCredential(rec.credential),
    subjectBindingSalt: Uint8Array.from(Buffer.from(rec.subjectBindingSaltHex, 'hex')),
    walletAddress: rec.walletAddress,
    storedAt: rec.storedAt,
  };
}
