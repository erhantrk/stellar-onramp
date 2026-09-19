/**
 * Session-JWT seam (ES256), FAIL CLOSED BY DEFAULT, REAL when configured.
 *
 * created, and §5.2 pins the token contract: "SDK → gateway | Session JWT (ES256),
 * `sub = wallet C-address`, ≤ 15 min, audience-scoped, DPoP-style proof-of-possession against the
 * passkey signer".
 *
 * WHAT EXISTS NOW vs WHAT §5.2 ULTIMATELY WANTS:
 *
 *   * ISSUANCE of an ES256 token meeting the sub / audience / ≤15-min-TTL clauses — REAL, below
 *     (`Es256SessionJwtIssuer`), built on the library's ES256 core (`signJws` / `verifyJws` in
 *     @stellaronramp/gateway, node:crypto only).
 *   * DPoP PROOF-OF-POSSESSION — **NOT IMPLEMENTED**. Today possession of the bearer token IS
 *     authentication; there is no per-request proof binding the token to the holder's passkey
 *     signer. That is strictly weaker than the §5.2 end-state and is recorded here rather than
 *     left silent: route-level auth checks the token's signature and claims, not the presenter's
 *     key possession. Closing this needs a DPoP proof verifier as its own run.
 *   * THE DEFAULT POSTURE SURVIVES: an `AppConfig` that omits `sessionJwtIssuer` still resolves
 *     to {@link UnimplementedSessionJwtIssuer} in buildServer → 501. This module adds the strong
 *     path; it does not replace the refusal. A misconfigured gateway answers "not built", never
 *     "here is an unsigned token".
 */

import { createPublicKey } from 'node:crypto';
import type { KeyObject } from 'node:crypto';

import { signJws } from '@stellaronramp/gateway';

import { UnimplementedError } from '../errors.js';

export const SESSION_JWT_MAX_TTL_SECONDS = 15 * 60;

export interface SessionJwtClaims {
  /** The session id the token authenticates. */
  readonly sessionId: string;
  /**
   * "`sub = wallet C-address`"). Widened from the original `{sessionId, issuedAt, expiresAt}`
   * shape: a claim set without the subject cannot produce a §5.2-conformant token.
   */
  readonly walletCAddr: string;
  /** Unix seconds. */
  readonly issuedAt: number;
  /** Unix seconds. Must satisfy `expiresAt - issuedAt <= SESSION_JWT_MAX_TTL_SECONDS`. */
  readonly expiresAt: number;
}

export interface SessionJwtIssuer {
  /** Issue a signed session JWT for a session. Throws on any refusal; no partial token. */
  issue(claims: SessionJwtClaims): Promise<string>;
}

/**
 * The REAL issuer: ES256 compact JWS over node:crypto via the library core, `sub` = wallet
 * C-address, audience-scoped, TTL hard-capped at 15 minutes.
 *
 * Construction is fail-closed by type: it requires an EC P-256 signing KeyObject up front (the
 * library refuses anything else at first use), an explicit `issuer` and an explicit `audience` —
 * there are no defaults to forget. The public half plus the issuer/audience pair are exposed so
 * the transport's auth config (types.ts `GatewayAuthConfig`) can be derived from ONE object,
 * making verifier/issuer disagreement a construction-time fact rather than a deployment accident.
 */
export class Es256SessionJwtIssuer implements SessionJwtIssuer {
  readonly #signingKey: KeyObject;
  /** Expected `iss` of tokens this issuer mints. */
  readonly issuer: string;
  /** Audience (`aud`) tokens are scoped to. */
  readonly audience: string;
  /** The PUBLIC half of the signing key — safe to hand to a verifier configuration. */
  readonly verificationKey: KeyObject;

  constructor(config: {
    /** EC P-256 private KeyObject (build with node:crypto; see @stellaronramp/gateway jws docs). */
    readonly signingKey: KeyObject;
    readonly issuer: string;
    readonly audience: string;
  }) {
    if (!config.issuer || !config.audience) {
      throw new Error('Es256SessionJwtIssuer requires a non-empty issuer and audience');
    }
    // Keep the constructor cheap and honest: the library re-checks curve/type on every sign, so
    // a wrong-family key cannot get two steps down this path.
    this.#signingKey = config.signingKey;
    this.verificationKey = createPublicKey(config.signingKey);
    this.issuer = config.issuer;
    this.audience = config.audience;
  }

  async issue(claims: SessionJwtClaims): Promise<string> {
    const ttl = claims.expiresAt - claims.issuedAt;
    if (!Number.isSafeInteger(ttl) || ttl <= 0) {
      throw new Error(
        `refusing to issue a session JWT whose validity window is not positive ` +
          `(issuedAt ${claims.issuedAt}, expiresAt ${claims.expiresAt})`,
      );
    }
    if (ttl > SESSION_JWT_MAX_TTL_SECONDS) {
      // Enforced HERE as well as by convention at the call site: a future handler bug that asks
      throw new Error(
        `refusing to issue a session JWT with a ${String(ttl)}s TTL; the design caps the ` +
          `SDK→gateway session token at ${SESSION_JWT_MAX_TTL_SECONDS}s (15 min)`,
      );
    }
    return signJws({
      privateKey: this.#signingKey,
      claims: {
        iss: this.issuer,
        sub: claims.walletCAddr,
        aud: this.audience,
        iat: claims.issuedAt,
        nbf: claims.issuedAt,
        exp: claims.expiresAt,
      },
    });
  }
}

export class UnimplementedSessionJwtIssuer implements SessionJwtIssuer {
  async issue(_claims: SessionJwtClaims): Promise<string> {
    throw new UnimplementedError(
      'SessionJwtIssuer (ES256/DPoP session token)',
    );
  }
}
