/**
 * The onboarding session store: `session_id -> wallet C-address` plus a coarse verdict.
 *
 * approved or rejected — a reason is the shape a PII leak takes, and the whole design keeps the
 * durable artefact to `{session_id, wallet_c_addr, status}`. This is an in-memory store, correct
 * for one process; a production gateway needs the Redis form behind the same interface.
 *
 * FAIL CLOSED: `assertApproved` throws on a missing OR not-approved session. There is no boolean
 * a caller can forget to check. The webhook path calls `setStatus(sessionId, 'approved')` only
 * after the HMAC + replay defence has cleared; issuance calls `assertApproved` and refuses
 * otherwise.
 */

import { randomUUID } from 'node:crypto';

export type SessionStatus = 'pending' | 'approved' | 'rejected';

export interface SessionRecord {
  readonly sessionId: string;
  readonly walletCAddr: string;
  readonly status: SessionStatus;
  readonly createdAtSeconds: number;
}

/** Thrown by `assertApproved` for a missing or not-yet-approved session. Maps to 409 in errors.ts. */
export class SessionNotApprovedError extends Error {
  override readonly name = 'SessionNotApprovedError';
  constructor(sessionId: string) {
    super(`session "${sessionId}" is not approved; nothing may be issued for it`);
  }
}

export interface SessionStore {
  /** Create a session for a wallet C-address. Returns the new session id. */
  create(walletCAddr: string, nowSeconds: number): Promise<string>;
  /** Read a session, or `undefined` if it does not exist. */
  get(sessionId: string): SessionRecord | undefined;
  /** Refuse unless the session exists AND is approved. */
  assertApproved(sessionId: string): void;
  /** Advance/regress a session's verdict. Status only — never a reason. */
  setStatus(sessionId: string, status: SessionStatus): void;
}

export class InMemorySessionStore implements SessionStore {
  readonly #sessions = new Map<string, SessionRecord>();

  async create(walletCAddr: string, nowSeconds: number): Promise<string> {
    const sessionId = randomUUID();
    this.#sessions.set(sessionId, {
      sessionId,
      walletCAddr,
      status: 'pending',
      createdAtSeconds: nowSeconds,
    });
    return sessionId;
  }

  get(sessionId: string): SessionRecord | undefined {
    return this.#sessions.get(sessionId);
  }

  assertApproved(sessionId: string): void {
    const session = this.#sessions.get(sessionId);
    if (session === undefined || session.status !== 'approved') {
      throw new SessionNotApprovedError(sessionId);
    }
  }

  setStatus(sessionId: string, status: SessionStatus): void {
    const session = this.#sessions.get(sessionId);
    if (session === undefined) {
      throw new SessionNotApprovedError(sessionId);
    }
    this.#sessions.set(sessionId, { ...session, status });
  }

  /** Test/diagnostic only. */
  get size(): number {
    return this.#sessions.size;
  }
}
