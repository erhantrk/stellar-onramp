/**
 * Shared status-list fixtures. NOT a test file — the vitest include is `test/ ** /*.test.ts`, so
 * nothing here is collected as a suite (the discipline test/chain/fakes.ts set).
 *
 * NO NETWORK. `FakeStatusListHttp` is the only transport any test in test/status uses, and the real
 * `FetchStatusListHttp` is never constructed outside an explicitly-gated live test.
 */

import { createPublicKey, createPrivateKey } from 'node:crypto';

import { publishStatusList } from '../../src/status/publisher.js';
import type { PublishStatusListRequest } from '../../src/status/publisher.js';
import type { StatusListCredentialDocument } from '../../src/status/credential.js';
import type {
  StatusListHttp,
  StatusListHttpResponse,
} from '../../src/status/resolver.js';

/** A test-only Ed25519 seed. Obviously not a real key. */
export const ISSUER_SEED = Uint8Array.from({ length: 32 }, (_, i) => i + 1);
/** A SECOND issuer, for the "correctly signed by the WRONG key" case. */
export const OTHER_SEED = Uint8Array.from({ length: 32 }, (_, i) => 0xa0 + i);

export const LIST_URL = 'https://status.stellaronramp.example/v1/status-list/issuer-1';
export const DOCUMENT_ISSUER = 'did:web:stellaronramp.example';
export const VERIFICATION_METHOD = `${DOCUMENT_ISSUER}#status-list-key-1`;
/** identity's 32-byte hex issuerId, as a StatusListRequest carries it. */
export const ISSUER_ID = 'b'.repeat(64);

/** Raw 32-byte Ed25519 public key for a seed, via node:crypto (no dependency). */
export function rawPublicKey(seed: Uint8Array): Uint8Array {
  const priv = createPrivateKey({
    key: Buffer.concat([
      Buffer.from('302e020100300506032b657004220420', 'hex'),
      Buffer.from(seed),
    ]),
    format: 'der',
    type: 'pkcs8',
  });
  const spki = createPublicKey(priv).export({ format: 'der', type: 'spki' });
  // SPKI for Ed25519 is a 12-byte prologue then the 32-byte key.
  return new Uint8Array(spki.subarray(12));
}

export const ISSUER_PUBLIC_KEY = rawPublicKey(ISSUER_SEED);
export const OTHER_PUBLIC_KEY = rawPublicKey(OTHER_SEED);

export const DEFAULT_VALID_FROM = 1_800_000_000;

/** Publish with sensible defaults; override anything. */
export function publish(
  over: Partial<PublishStatusListRequest> & { readonly revoked: readonly number[] },
): Promise<StatusListCredentialDocument> {
  return publishStatusList({
    url: LIST_URL,
    issuer: DOCUMENT_ISSUER,
    verificationMethod: VERIFICATION_METHOD,
    statusPurpose: 'revocation',
    validFromSeconds: DEFAULT_VALID_FROM,
    signingKey: { seed: ISSUER_SEED },
    ...over,
  });
}

/** One scripted hop. `body` defaults to the JSON of `document`. */
export interface ScriptedHop {
  readonly status?: number;
  readonly headers?: Readonly<Record<string, string | undefined>>;
  readonly body?: Uint8Array | string;
  readonly document?: unknown;
  /** Throw instead of responding, to model a transport failure or a timeout. */
  readonly throws?: unknown;
}

/**
 * A `StatusListHttp` that replays a script. Records every URL it was asked for, so a test can assert
 * the resolver followed the redirect chain ITSELF rather than delegating it to the transport.
 */
export class FakeStatusListHttp implements StatusListHttp {
  readonly urls: string[] = [];
  readonly options: Array<{ timeoutMs: number; maxBytes: number }> = [];
  #script: ScriptedHop[];
  readonly #loop: ScriptedHop | undefined;

  constructor(script: ScriptedHop | ScriptedHop[], loopLast = false) {
    this.#script = Array.isArray(script) ? [...script] : [script];
    this.#loop = loopLast ? this.#script[this.#script.length - 1] : undefined;
  }

  async get(
    url: string,
    options: { readonly timeoutMs: number; readonly maxBytes: number },
  ): Promise<StatusListHttpResponse> {
    this.urls.push(url);
    this.options.push({ ...options });
    const hop = this.#script.shift() ?? this.#loop;
    if (hop === undefined) {
      throw new Error(`FakeStatusListHttp: no scripted response for ${url}`);
    }
    if (hop.throws !== undefined) throw hop.throws;
    const body =
      hop.body !== undefined
        ? typeof hop.body === 'string'
          ? Buffer.from(hop.body, 'utf8')
          : hop.body
        : Buffer.from(JSON.stringify(hop.document ?? {}), 'utf8');
    return { status: hop.status ?? 200, headers: hop.headers ?? {}, body };
  }

  get callCount(): number {
    return this.urls.length;
  }
}
