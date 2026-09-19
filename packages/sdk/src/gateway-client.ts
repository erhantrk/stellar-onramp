/**
 * Typed client for the gateway's HTTP surface: the public documents (`.well-known/issuer`,
 * `schema/{version}`, `status-list/{issuer_id}`, `healthz`, `readyz`) and
 * `POST /v1/credentials/issue`. Session creation is the host application's onboarding step; the
 * client is handed the resulting session token in its config.
 */

import type { SerializedCredential } from '@stellaronramp/identity';

export class GatewayClientError extends Error {
  // Typed as `string` (not the literal) because the subclasses below override it with their own
  // names; a literal-typed base field would make the subclass objects unassignable to the base
  // under strict property checks. `instanceof` is the mapping mechanism either way.
  override readonly name: string = 'GatewayClientError';
  readonly status: number;
  /** Machine code from the response envelope when present (`{error: {code}}`), else `http_<n>`. */
  readonly code: string;
  readonly retriable: boolean;

  constructor(
    message: string,
    shape: { readonly status: number; readonly code?: string; readonly retriable: boolean },
  ) {
    super(message);
    this.name = 'GatewayClientError';
    this.status = shape.status;
    this.code = shape.code ?? `http_${String(shape.status)}`;
    this.retriable = shape.retriable;
  }
}

/** 404 — a wrong version, an issuer id the gateway does not serve. Not retriable. */
export class GatewayNotFoundError extends GatewayClientError {
  override readonly name = 'GatewayNotFoundError';
}
/** 409 — the load-bearing one for `issueCredential`: session exists but is not approved. */
export class GatewaySessionNotApprovedError extends GatewayClientError {
  override readonly name = 'GatewaySessionNotApprovedError';
}
/**
 * 401 — the gateway's route auth refused the presented credential for `issueCredential`: none
 * configured, expired (a session JWT lives ≤ 15 min), or minted under another key/issuer. The
 * message is FIXED — no reason strings, no echoed token (same rule as the server's own 401).
 */
export class GatewayUnauthorizedError extends GatewayClientError {
  override readonly name = 'GatewayUnauthorizedError';
}
/** 403 — a VALID credential of the WRONG mode (e.g. an anchor SEP-10 token at a session route). */
export class GatewayForbiddenError extends GatewayClientError {
  override readonly name = 'GatewayForbiddenError';
}
/** 500/502/503/504 — transport- or server-side; retry WITH BACKOFF may help. */
export class GatewayUnavailableError extends GatewayClientError {
  override readonly name = 'GatewayUnavailableError';
}
/** 501 — a seam the deployment has not implemented. Retrying is a loop. */
export class GatewayNotImplementedError extends GatewayClientError {
  override readonly name = 'GatewayNotImplementedError';
}
/** Any other non-2xx — surfaced with its status rather than collapsed into a generic failure. */
export class GatewayUnexpectedStatusError extends GatewayClientError {
  override readonly name = 'GatewayUnexpectedStatusError';
}

/** `GET /v1/.well-known/issuer` — every field derived server-side; see handlers/well-known.ts. */
export interface IssuerDocument {
  readonly issuer_id: string;
  readonly pk_g2_compressed: string;
  readonly pk_g2_uncompressed: string;
  readonly ciphersuite: string;
  readonly schema_version: string;
  readonly registry_contract_id: string;
  readonly gate_contract_id: string;
  readonly network: string;
  readonly network_passphrase: string;
  readonly generators_root: string;
  readonly generators_encoding: string;
  readonly generators: readonly string[];
}

/** `GET /v1/schema/{version}` — the frozen v1 schema projection. */
export interface SchemaDocument {
  readonly schema_version: string;
  readonly attribute_count: number;
  readonly ciphersuite: string;
  readonly credential_header: string;
  readonly claim_index: Readonly<Record<string, number>>;
}

/**
 * `POST /v1/credentials/issue` — the 201 body. The wallet comes from the SESSION (the client
 * cannot bind a credential to a wallet it did not onboard), and the salt is returned exactly
 * once: the gateway never persists it, so losing it after this response makes the credential
 * unverifiable forever (see src/store.ts).
 */
export interface IssuedCredentialResponse {
  readonly credential: SerializedCredential;
  readonly claim_bitmap: number;
  readonly revocation_index: number;
  /** 32-byte subject-binding salt, lowercase hex. Persist it beside the credential. */
  readonly subject_binding_salt: string;
}

export interface IssueCredentialInput {
  readonly sessionId: string;
  /** Exactly the six booleans the handler reads; any non-boolean is a 400. */
  readonly claims: {
    readonly over18: boolean;
    readonly over21: boolean;
    readonly notSanctioned: boolean;
    readonly notPep: boolean;
    readonly jurisdictionOk: boolean;
    readonly livenessOk: boolean;
  };
  /** Optional credential lifetime (unix seconds). Server defaults to now + 24 h. */
  readonly expiresAt?: number;
}

export interface GatewayClientConfig {
  /** Base URL, no trailing slash — e.g. `http://127.0.0.1:8080`. */
  readonly baseUrl: string;
  /**
   * `/v1/credentials/issue` — the one auth-gated call this client speaks. A string, or an async
   * supplier invoked per call so a host app can re-mint before expiry (the token's TTL is ≤ 15
   * min; a static string WILL start answering 401 — `GatewayUnauthorizedError` — when it does).
   *
   * Optional in the type for backward compatibility with public-route-only usage, but
   * `issueCredential` CANNOT succeed against any gateway built since route auth landed without
   * it. Obtain it from your onboarding flow's `POST /v1/session` response (`session_token`
   * carries the session JWT today); never log it.
   */
  readonly sessionToken?: string | (() => string | Promise<string>);
  /**
   * Injectable fetch (undici's global by default). Injected so tests bind a local server and so
   * a browser app can supply its own (credentials policy, interceptors). The client adds its OWN
   * Authorization header at the call site from `sessionToken`; a custom fetchImpl could still add
   * or rewrite headers — that is the caller owning their transport, and the gateway enforces
   * verification regardless of what any client sends.
   */
  readonly fetchImpl?: typeof fetch;
  readonly timeoutMs?: number;
}

function toGatewayError(status: number, bodyText: string): GatewayClientError {
  // Parse the envelope for its machine code, but never branch on its prose. The shape is built
  // conditionally (not with a `string | undefined`) because `exactOptionalPropertyTypes` is on.
  let code: string | undefined;
  try {
    const parsed = JSON.parse(bodyText) as { error?: { code?: unknown } };
    if (typeof parsed.error?.['code'] === 'string') code = parsed.error['code'];
  } catch {
    /* non-JSON body — the status still classifies */
  }
  const shape: { readonly status: number; readonly code?: string; readonly retriable: boolean } =
    code === undefined
      ? { status, retriable: status >= 500 && status !== 501 }
      : { status, code, retriable: status >= 500 && status !== 501 };
  if (status === 404) return new GatewayNotFoundError('not found', shape);
  if (status === 401) return new GatewayUnauthorizedError('authentication required by the gateway', shape);
  if (status === 403) return new GatewayForbiddenError('credential valid but insufficient for this surface', shape);
  if (status === 409) {
    return new GatewaySessionNotApprovedError(
      'the session is not approved; a credential cannot be issued for it yet ' +
        '(only the KYC provider verdict can approve a session)',
      shape,
    );
  }
  if (status === 501) return new GatewayNotImplementedError('not implemented on this deployment', shape);
  if (status >= 500) return new GatewayUnavailableError('gateway unavailable', shape);
  return new GatewayUnexpectedStatusError(`unexpected status ${String(status)}`, shape);
}

export class GatewayClient {
  readonly #baseUrl: string;
  readonly #fetchImpl: typeof fetch;
  readonly #timeoutMs: number;
  readonly #sessionToken: string | (() => string | Promise<string>) | undefined;

  constructor(config: GatewayClientConfig) {
    this.#baseUrl = config.baseUrl.replace(/\/+$/, '');
    this.#fetchImpl = config.fetchImpl ?? fetch;
    this.#timeoutMs = config.timeoutMs ?? 10_000;
    this.#sessionToken = config.sessionToken;
  }

  /** Resolve the configured session credential to a raw JWT for the Authorization header. */
  async #resolveSessionToken(): Promise<string | undefined> {
    const t = this.#sessionToken;
    if (t === undefined) return undefined;
    return typeof t === 'string' ? t : t();
  }

  async #get<T>(path: string): Promise<T> {
    const res = await this.#fetchImpl(`${this.#baseUrl}${path}`, {
      method: 'GET',
      signal: AbortSignal.timeout(this.#timeoutMs),
      // No credentials on the GETs, deliberately: they are public routes (`auth: 'none'`), and
      // presenting a session JWT where it is not the route's mode can only classify as 403 noise.
    });
    const text = await res.text();
    if (!res.ok) throw toGatewayError(res.status, text);
    return JSON.parse(text) as T;
  }

  async #post<T>(path: string, body: unknown, headers: Record<string, string> = {}): Promise<T> {
    const res = await this.#fetchImpl(`${this.#baseUrl}${path}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', ...headers },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(this.#timeoutMs),
    });
    const text = await res.text();
    if (!res.ok) throw toGatewayError(res.status, text);
    return JSON.parse(text) as T;
  }

  wellKnownIssuer(): Promise<IssuerDocument> {
    return this.#get('/v1/.well-known/issuer');
  }

  schema(version: string): Promise<SchemaDocument> {
    return this.#get(`/v1/schema/${encodeURIComponent(version)}`);
  }

  /** The signed Bitstring Status List for an issuer id. 404 for any id but the gateway's own. */
  statusList(issuerId: string): Promise<unknown> {
    return this.#get(`/v1/status-list/${encodeURIComponent(issuerId)}`);
  }

  healthz(): Promise<{ readonly status: string; readonly service: string }> {
    return this.#get('/healthz');
  }

  readyz(): Promise<{ readonly status: string; readonly network: string }> {
    return this.#get('/readyz');
  }

  /**
   * `POST /v1/credentials/issue`. AUTH-GATED since the gateway-auth track: presents
   * `sessionToken` as `Authorization: Bearer …`, and the gateway additionally binds the token's
   * subject (the wallet C-address) to the addressed session — a valid token for wallet A cannot
   * issue against wallet B's session (403).
   *
   *   * 201 → {@link IssuedCredentialResponse};
   *   * 401 → GatewayUnauthorizedError (no/expired/wrong-key session credential — re-mint);
   *   * 403 → GatewayForbiddenError (a VALID credential of another mode, or another wallet's
   *     session — the gateway's loud subject-binding refusal).
   */
  async issueCredential(input: IssueCredentialInput): Promise<IssuedCredentialResponse> {
    const token = await this.#resolveSessionToken();
    return this.#post('/v1/credentials/issue', {
      sessionId: input.sessionId,
      ...input.claims,
      ...(input.expiresAt === undefined ? {} : { expiresAt: input.expiresAt }),
    }, token === undefined ? {} : { authorization: `Bearer ${token}` });
  }
}
