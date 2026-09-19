/**
 * The gateway's configuration and routing types.
 *
 * `AppConfig` is everything `buildServer` needs, all injected: the issuer key material, the
 * status-list signing key, and the seams (session store, revocation-index allocator, session
 * token issuer, KYC applicant creator). Nothing reaches the network unless a seam given here
 * does; the defaults for the optional seams fail closed with 501.
 */

import type { IncomingMessage, ServerResponse } from 'node:http';
import type { KeyObject } from 'node:crypto';

import type { RevocationIndexAllocator } from '@stellaronramp/gateway';

import type { SessionStore } from './seams/session-store.js';
import type { SessionJwtIssuer } from './seams/session-jwt.js';
import type { KycApplicantCreator } from './seams/kyc-applicant.js';

/* -------------------------------------------------------------------------- */
/* Status-list store (app-owned)                                               */
/* -------------------------------------------------------------------------- */

/** The revoked indexes the published status list must carry. */
export interface StatusListStore {
  revokedIndexes(): readonly number[];
}

export class InMemoryStatusListStore implements StatusListStore {
  readonly #revoked = new Set<number>();

  revoke(index: number): void {
    this.#revoked.add(index);
  }

  clear(index: number): void {
    this.#revoked.delete(index);
  }

  revokedIndexes(): readonly number[] {
    return [...this.#revoked];
  }
}

/* -------------------------------------------------------------------------- */
/* AppConfig                                                                   */
/* -------------------------------------------------------------------------- */

export interface AppConfig {
  readonly network: 'testnet' | 'mainnet';
  readonly networkPassphrase: string;
  readonly kycGateContractId: string;
  readonly kycRegistryContractId: string;

  /** BBS+ issuer key pair; the public key is the one registered on `kyc-registry`. */
  readonly issuerPublicKey: Uint8Array;
  readonly issuerSecretKey: Uint8Array;

  /** Status list: where it is published, what signs it, and which indexes are revoked. */
  readonly statusListUrl: string;
  readonly statusListSigningKey: { readonly seed?: Uint8Array; readonly pkcs8Der?: Uint8Array };
  readonly verificationMethod: string;
  readonly statusListStore: StatusListStore;

  readonly sessionStore: SessionStore;
  readonly revocationIndexAllocator: RevocationIndexAllocator;
  readonly now: () => number;

  /** Optional seams. Absent, the routes that need them answer 501. */
  readonly sessionJwtIssuer?: SessionJwtIssuer;
  readonly kycApplicantCreator?: KycApplicantCreator;
  readonly auth?: GatewayAuthConfig;
}

/** Verification material for the session JWT the gateway issues. */
export interface GatewayAuthConfig {
  readonly sessionJwt: {
    readonly publicKey: KeyObject;
    readonly issuer: string;
    readonly audience: string;
  };
}

export type ResolvedAppConfig = AppConfig &
  Required<Pick<AppConfig, 'sessionJwtIssuer' | 'kycApplicantCreator'>>;

/* -------------------------------------------------------------------------- */
/* Routing                                                                     */
/* -------------------------------------------------------------------------- */

export interface RouteParams {
  [name: string]: string | undefined;
}

export type AuthenticatedRequest = {
  readonly kind: 'session';
  /** Verified token subject: the wallet contract address. */
  readonly subject: string;
};

export type RouteAuth = 'none' | 'session';

export interface RouteContext {
  readonly request: IncomingMessage;
  readonly response: ServerResponse;
  readonly requestId: string;
  readonly method: string;
  readonly path: string;
  readonly params: RouteParams;
  readonly rawBody: Buffer;
  readonly json: unknown;
  readonly auth?: AuthenticatedRequest;
}

export type RouteHandler = (ctx: RouteContext) => Promise<void> | void;

export interface Route {
  readonly method: string;
  readonly pathTemplate: string;
  readonly jsonBody: boolean;
  readonly auth?: RouteAuth;
  readonly paramPatterns?: Readonly<Record<string, RegExp>>;
  readonly handler: RouteHandler;
}
