/**
 * THE HARDENED STATUS LIST DEREFERENCER. This is the highest-value thing in this package and nothing in
 * this repo has ever had it.
 *
 * WHAT EXISTED BEFORE. `@stellaronramp/identity` verifies the status list ENCODING and reads the BIT.
 * Its own src/status-list.ts header says where the boundary is: "It deliberately does NOT implement
 * §3.2 step 4 ('Dereference the statusListCredential URL'): that is a network fetch, and
 * @stellaronramp/identity makes no network calls. The CALLER dereferences the URL, verifies the status
 * list credential's own proof, and hands us the resulting object — or hands us a resolver callback that
 * does so." Nobody had written that caller. So: nothing fetched the URL, nothing verified that
 * document's own signature, nothing checked its `validUntil`, nothing cached it, nothing enforced
 * MITM WHO CAN UN-REVOKE ANYBODY" and "a caller who caches a list for a week has a week-long
 * revocation window".
 *
 * THIS FILE NEEDS ZERO WRITES TO packages/identity. `VerifyOptions.statusList` already accepts
 * `BitstringStatusList | StatusListResolver | UnsafeSkip`, where `StatusListResolver` is
 * `(request: StatusListRequest) => BitstringStatusList | Promise<BitstringStatusList>` and
 * `StatusListRequest` is `{revocationIndex, issuerId, statusPurpose}`. `HardenedStatusListResolver
 * .asStatusListResolver()` returns exactly that function type. Verified by reading
 * packages/identity/src/status-list.ts, not by trusting a brief.
 *
 * FAIL CLOSED, ALWAYS, BY THROWING. identity converts a resolver throw into
 * `reason: 'status-list-invalid'`, which is `valid: false`. Returning an EMPTY list instead of throwing
 * would silently un-revoke everyone — an all-zero 131,072-entry bitstring is a perfectly well-formed
 * status list that says nobody is revoked. There is no code path in this file that returns a
 * synthesised list, and test/status/resolver.test.ts asserts a resolver failure produces `valid: false`
 * out of `verifyDetailed`, not merely that the resolver threw.
 */

import { MAX_STATUS_LIST_BYTES, decodeStatusList } from '@stellaronramp/identity';
import type { BitstringStatusList, StatusListRequest, StatusPurpose } from '@stellaronramp/identity';

import {
  StatusCredentialError,
  parseXsdDateTime,
  toBitstringStatusList,
  verifyStatusListCredential,
} from './credential.js';
import type { StatusListCredentialDocument } from './credential.js';
import { assertHttpsUrl } from './publisher.js';

export class StatusListResolutionError extends Error {
  override readonly name = 'StatusListResolutionError';
  readonly reason: StatusListResolutionReason;
  constructor(reason: StatusListResolutionReason, message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.reason = reason;
  }
}

export type StatusListResolutionReason =
  | 'unknown-issuer'
  | 'issuer-undisclosed'
  | 'insecure-url'
  | 'redirect-downgrade'
  | 'too-many-redirects'
  | 'http-error'
  | 'response-too-large'
  | 'timeout'
  | 'transport'
  | 'malformed'
  | 'proof-invalid'
  | 'not-yet-valid'
  | 'expired'
  | 'stale'
  | 'purpose-mismatch';

/**
 * VERIFIER-SIDE freshness bound, in seconds. 5 minutes.
 *
 * THIS IS THE POINT OF THE WHOLE MODULE AND IT IS INDEPENDENT OF `validUntil` ON PURPOSE.
 * `validUntil` is the ISSUER's claim about how long the document may be believed; this is the
 * VERIFIER's own bound, and it lets a verifier be STRICTER than the issuer without asking the issuer to
 * revocation window" is a time-of-check/time-of-use gap, and the only closure for it is a bound the
 * relying party chooses.
 *
 * It is measured from the document's `validFrom` (the issuer's statement of when the bits were true),
 * NOT from when we fetched it. Measuring from the fetch would let a mirror serve a month-old document
 * forever: it would be "fresh" every time we re-fetched it. That distinction is the difference between
 * a freshness check and a cache-age check, and both are implemented here — `maxAgeSeconds` bounds the
 * DOCUMENT and `cacheTtlSeconds` bounds our COPY of it.
 */
export const DEFAULT_STATUS_LIST_MAX_AGE_SECONDS = 300;

/** How long our own cached copy may be served without a re-fetch. Bounded by `maxAgeSeconds`. */
export const DEFAULT_STATUS_LIST_CACHE_TTL_SECONDS = 60;

/** Fetch timeout. A verification that hangs is a verification that never fails closed. */
export const DEFAULT_STATUS_LIST_TIMEOUT_MS = 5_000;

/**
 * Redirect cap. Three is generous for a static document behind a CDN and it bounds a redirect loop.
 * Each hop is re-checked for an HTTPS downgrade, which is the attack this cap exists alongside: an
 * `https://` URL that 302s to `http://` is a plaintext fetch that LOOKS secure in the config.
 */
export const MAX_STATUS_LIST_REDIRECTS = 3;

/** One pinned issuer. The key is CONFIGURATION; it is never read from the fetched document. */
export interface PinnedStatusListIssuer {
  /** identity's 32-byte hex `issuerId`, matched against `StatusListRequest.issuerId`. */
  readonly issuerId: string;
  /** HTTPS URL of the list. */
  readonly url: string;
  /** Raw 32-byte Ed25519 public key. Pinned. */
  readonly publicKeyRaw: Uint8Array;
  /** The `issuer` value the document must carry. */
  readonly documentIssuer: string;
  /** Optional: the exact `proof.verificationMethod` label required. */
  readonly verificationMethod?: string;
}

/** What one HTTP hop returned. Deliberately minimal so a fake is a few lines. */
export interface StatusListHttpResponse {
  readonly status: number;
  /** Lowercase header names. Only `location` and `content-length` are read. */
  readonly headers: Readonly<Record<string, string | undefined>>;
  /** Response body. Implementations MUST abort past `maxBytes` rather than buffer then check. */
  readonly body: Uint8Array;
}

/**
 * The ONE network method. Mentions no SDK type and takes no options object it has to interpret, so a
 * fake is five lines — the shape test/chain/fakes.ts settled on.
 *
 * `redirect: 'manual'` semantics are REQUIRED of implementations: the resolver follows redirects itself
 * so it can re-run the HTTPS check on every hop and count them. An implementation that follows
 * redirects internally silently disables both controls, which is why the contract is stated here and
 * asserted by a test that hands the resolver a 302 and expects it to be visible.
 */
export interface StatusListHttp {
  get(
    url: string,
    options: { readonly timeoutMs: number; readonly maxBytes: number },
  ): Promise<StatusListHttpResponse>;
}

/**
 * `globalThis.fetch` implementation. Node >= 22, zero dependencies.
 *
 * THREE THINGS IT DOES THAT A ONE-LINER DOES NOT:
 *
 *   1. `redirect: 'manual'`, so the resolver sees every hop.
 *   2. `AbortController` + `setTimeout`, so a hung origin cannot hang a verification. The timer is
 *      cleared in a `finally`, because a leaked timer keeps the event loop alive and turns a passing
 *      test suite into one that never exits.
 *   3. It reads the body through a STREAM READER and aborts the moment the accumulated length exceeds
 *      `maxBytes`, rather than `await response.arrayBuffer()` then checking the length. The difference
 *      matters: `arrayBuffer()` on a 4 GB response allocates 4 GB before you get to check.
 *      `content-length`, when present, is checked BEFORE reading a single byte — but it is a HINT from
 *      the server and is not trusted as a bound, which is why the streaming cap exists too.
 */
export class FetchStatusListHttp implements StatusListHttp {
  async get(
    url: string,
    options: { readonly timeoutMs: number; readonly maxBytes: number },
  ): Promise<StatusListHttpResponse> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), options.timeoutMs);
    try {
      const response = await fetch(url, {
        method: 'GET',
        redirect: 'manual',
        signal: controller.signal,
        headers: { accept: 'application/json' },
      });
      const headers: Record<string, string | undefined> = {};
      response.headers.forEach((value, key) => {
        headers[key.toLowerCase()] = value;
      });
      const declared = headers['content-length'];
      if (declared !== undefined) {
        const n = Number(declared);
        if (Number.isFinite(n) && n > options.maxBytes) {
          // Refuse before reading a byte. The header is a hint, not a bound — hence the stream cap.
          throw new StatusListResolutionError(
            'response-too-large',
            `refusing a status list whose content-length declares ${n} bytes, past the ` +
              `${options.maxBytes}-byte cap`,
          );
        }
      }
      const body = await readCapped(response, options.maxBytes);
      return { status: response.status, headers, body };
    } finally {
      clearTimeout(timer);
    }
  }
}

async function readCapped(response: Response, maxBytes: number): Promise<Uint8Array> {
  const stream = response.body;
  if (stream === null) return new Uint8Array(0);
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value === undefined) continue;
      total += value.length;
      if (total > maxBytes) {
        await reader.cancel().catch(() => undefined);
        throw new StatusListResolutionError(
          'response-too-large',
          `refusing a status list body past the ${maxBytes}-byte cap; the read was aborted rather ` +
            'than buffered and then measured',
        );
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.length;
  }
  return out;
}

export interface HardenedStatusListResolverConfig {
  readonly issuers: readonly PinnedStatusListIssuer[];
  readonly http: StatusListHttp;
  /** Unix seconds. Injected so freshness is testable and not a wall-clock race. */
  readonly now: () => number;
  /** Verifier-side document freshness bound. Defaults to `DEFAULT_STATUS_LIST_MAX_AGE_SECONDS`. */
  readonly maxAgeSeconds?: number;
  /** How long our cached copy is served. Defaults to `DEFAULT_STATUS_LIST_CACHE_TTL_SECONDS`. */
  readonly cacheTtlSeconds?: number;
  readonly timeoutMs?: number;
  readonly maxBytes?: number;
  readonly maxRedirects?: number;
  /**
   * Used when `StatusListRequest.issuerId` is `undefined` — i.e. the proof did not disclose claim
   * index 1. MUST be set explicitly to allow that; otherwise resolution fails closed.
   *
   * Defaulting silently would be wrong in a multi-issuer world: "resolve against whichever issuer we
   * happen to have configured first" is how a credential from issuer A gets its revocation status read
   * out of issuer B's list, which is an un-revoke for anyone A revoked.
   */
  readonly defaultIssuerId?: string;
}

/** What a caller gets to ask about the bit it is trusting. */
export interface StatusListProvenance {
  readonly url: string;
  readonly issuerId: string;
  /** Age of the DOCUMENT, from its `validFrom`, in seconds. */
  readonly documentAgeSeconds: number;
  /** Age of OUR COPY, in seconds. 0 on a fresh fetch. */
  readonly cacheAgeSeconds: number;
  /** The verifier-side bound that was applied. */
  readonly maxAgeSeconds: number;
  /** `validUntil` as unix seconds. */
  readonly validUntilSeconds: number;
  /** Whether this resolution was served from cache. */
  readonly fromCache: boolean;
}

interface CacheEntry {
  readonly document: StatusListCredentialDocument;
  readonly list: BitstringStatusList;
  readonly validFromSeconds: number;
  readonly validUntilSeconds: number;
  readonly fetchedAtSeconds: number;
}

/**
 * The dereferencer.
 *
 * Every control has its own test in test/status/resolver.test.ts, and the round trip
 * (publish -> dereference -> `verifyDetailed` says `revoked`) is in test/status/roundtrip.test.ts.
 */
export class HardenedStatusListResolver {
  readonly #issuers: Map<string, PinnedStatusListIssuer>;
  readonly #http: StatusListHttp;
  readonly #now: () => number;
  readonly #maxAge: number;
  readonly #cacheTtl: number;
  readonly #timeoutMs: number;
  readonly #maxBytes: number;
  readonly #maxRedirects: number;
  readonly #defaultIssuerId: string | undefined;
  readonly #cache = new Map<string, CacheEntry>();
  /** Provenance of the most recent resolution, so a caller can ask "how old is this bit?". */
  #lastProvenance: StatusListProvenance | undefined;

  constructor(config: HardenedStatusListResolverConfig) {
    if (!Array.isArray(config.issuers) || config.issuers.length === 0) {
      throw new StatusListResolutionError(
        'unknown-issuer',
        'refusing to build a status list resolver with no pinned issuers; a resolver with no pinned ' +
          'key would have to take the key from the document, and every forgery is self-consistent',
      );
    }
    this.#issuers = new Map();
    for (const issuer of config.issuers) {
      assertHttpsUrl(issuer.url, `pinned status list URL for issuer ${issuer.issuerId}`);
      if (!(issuer.publicKeyRaw instanceof Uint8Array) || issuer.publicKeyRaw.length !== 32) {
        throw new StatusListResolutionError(
          'proof-invalid',
          `refusing to pin issuer ${issuer.issuerId} without a 32-byte raw Ed25519 public key`,
        );
      }
      if (this.#issuers.has(issuer.issuerId)) {
        throw new StatusListResolutionError(
          'unknown-issuer',
          `refusing two pinned configurations for issuer ${issuer.issuerId}; the later one would ` +
            'silently win and nobody would know which key is in force',
        );
      }
      this.#issuers.set(issuer.issuerId, issuer);
    }
    this.#http = config.http;
    this.#now = config.now;
    this.#maxAge = config.maxAgeSeconds ?? DEFAULT_STATUS_LIST_MAX_AGE_SECONDS;
    this.#cacheTtl = config.cacheTtlSeconds ?? DEFAULT_STATUS_LIST_CACHE_TTL_SECONDS;
    this.#timeoutMs = config.timeoutMs ?? DEFAULT_STATUS_LIST_TIMEOUT_MS;
    this.#maxBytes = config.maxBytes ?? MAX_STATUS_LIST_BYTES;
    this.#maxRedirects = config.maxRedirects ?? MAX_STATUS_LIST_REDIRECTS;
    this.#defaultIssuerId = config.defaultIssuerId;
    if (!Number.isFinite(this.#maxAge) || this.#maxAge <= 0) {
      throw new StatusListResolutionError(
        'stale',
        `refusing a status list freshness bound of ${String(this.#maxAge)}s; a non-positive or ` +
          'infinite bound is the same as no bound, which is the week-long revocation window ' +
          'the status-list design note warns about',
      );
    }
    if (this.#cacheTtl > this.#maxAge) {
      // A cache that outlives the freshness bound serves documents it would refuse to fetch.
      throw new StatusListResolutionError(
        'stale',
        `refusing a cache TTL (${this.#cacheTtl}s) longer than the freshness bound ` +
          `(${this.#maxAge}s); the cache would serve a copy the freshness check would reject, which ` +
          'is the time-of-check/time-of-use gap with extra steps',
      );
    }
  }

  /** Provenance of the last successful resolution. `undefined` before the first one. */
  get lastProvenance(): StatusListProvenance | undefined {
    return this.#lastProvenance;
  }

  /**
   * The exact function type `VerifyOptions.statusList` accepts. Bound so it can be passed as a value.
   */
  asStatusListResolver(): (request: StatusListRequest) => Promise<BitstringStatusList> {
    return (request: StatusListRequest) => this.resolve(request);
  }

  async resolve(request: StatusListRequest): Promise<BitstringStatusList> {
    const issuerId = request.issuerId ?? this.#defaultIssuerId;
    if (issuerId === undefined) {
      throw new StatusListResolutionError(
        'issuer-undisclosed',
        'refusing to resolve a status list for a proof that did not disclose issuerId (claim index ' +
          '1) when no defaultIssuerId is configured. Guessing an issuer would read one issuer\'s ' +
          "revocation bit out of another issuer's list, which un-revokes anybody the first one " +
          'revoked. Compose credentialAudit() into the predicate to disclose index 1, or set ' +
          'defaultIssuerId explicitly for a single-issuer deployment.',
      );
    }
    const pinned = this.#issuers.get(issuerId);
    if (pinned === undefined) {
      throw new StatusListResolutionError(
        'unknown-issuer',
        `refusing to resolve a status list for unpinned issuer "${issuerId.slice(0, 96)}". An ` +
          'unpinned issuer has no pinned key, and a list we cannot authenticate is not evidence ' +
          'that a credential is live.',
      );
    }

    const now = this.#now();
    const cached = this.#cache.get(pinned.url);
    if (cached !== undefined && now - cached.fetchedAtSeconds < this.#cacheTtl) {
      // Even a cache hit is re-checked against the clock: the document may have expired or gone stale
      // while it sat in the cache, and serving it because "we already validated it" is exactly the
      // time-of-check/time-of-use bug.
      this.#assertTemporallyUsable(cached, now, pinned);
      this.#assertPurpose(cached.list, request.statusPurpose, pinned.url);
      this.#lastProvenance = {
        url: pinned.url,
        issuerId,
        documentAgeSeconds: now - cached.validFromSeconds,
        cacheAgeSeconds: now - cached.fetchedAtSeconds,
        maxAgeSeconds: this.#maxAge,
        validUntilSeconds: cached.validUntilSeconds,
        fromCache: true,
      };
      return cached.list;
    }

    const entry = await this.#fetchAndVerify(pinned, now);
    this.#assertTemporallyUsable(entry, now, pinned);
    this.#assertPurpose(entry.list, request.statusPurpose, pinned.url);
    // Cached only AFTER every check passes. Caching first would mean one bad document poisons the
    // cache for its whole TTL, turning a single bad response into a sustained outage.
    this.#cache.set(pinned.url, entry);
    this.#lastProvenance = {
      url: pinned.url,
      issuerId,
      documentAgeSeconds: now - entry.validFromSeconds,
      cacheAgeSeconds: 0,
      maxAgeSeconds: this.#maxAge,
      validUntilSeconds: entry.validUntilSeconds,
      fromCache: false,
    };
    return entry.list;
  }

  /**
   * Fetch, following redirects OURSELVES so that every hop is re-checked for a scheme downgrade and the
   * hops are counted.
   */
  async #fetchAndVerify(pinned: PinnedStatusListIssuer, now: number): Promise<CacheEntry> {
    let url = assertHttpsUrl(pinned.url).toString();
    let hops = 0;
    let response: StatusListHttpResponse;
    for (;;) {
      try {
        response = await this.#http.get(url, {
          timeoutMs: this.#timeoutMs,
          maxBytes: this.#maxBytes,
        });
      } catch (cause) {
        if (cause instanceof StatusListResolutionError) throw cause;
        const aborted =
          cause !== null && typeof cause === 'object' && (cause as { name?: string }).name === 'AbortError';
        throw new StatusListResolutionError(
          aborted ? 'timeout' : 'transport',
          aborted
            ? `refusing to verify against a status list whose fetch timed out after ` +
              `${this.#timeoutMs}ms; a hung fetch is a verification that never completes, which is ` +
              'worse than one that fails'
            : `refusing to verify against a status list that could not be fetched from ${url}`,
          { cause },
        );
      }
      if (response.status >= 300 && response.status < 400) {
        hops += 1;
        if (hops > this.#maxRedirects) {
          throw new StatusListResolutionError(
            'too-many-redirects',
            `refusing a status list after ${hops} redirects (cap ${this.#maxRedirects}); an ` +
              'unbounded redirect chain is a fetch that never ends',
          );
        }
        const location = response.headers['location'];
        if (location === undefined || location === '') {
          throw new StatusListResolutionError(
            'malformed',
            `refusing a status list whose ${response.status} response carries no Location header`,
          );
        }
        // Resolved against the CURRENT url so a relative Location works, then re-checked. This is
        // where the downgrade attack is caught: an https:// URL that 302s to http:// LOOKS secure in
        // the config and is a plaintext fetch on the wire.
        let next: URL;
        try {
          next = new URL(location, url);
        } catch (cause) {
          throw new StatusListResolutionError('malformed', 'status list redirect Location is not a URL', {
            cause,
          });
        }
        if (next.protocol !== 'https:') {
          throw new StatusListResolutionError(
            'redirect-downgrade',
            `refusing a status list redirect from ${url} to scheme "${next.protocol}". A redirect ` +
              'that downgrades to plain HTTP hands an on-path attacker the ability to serve an ' +
              'all-zero bitstring and un-revoke every holder, while the configured URL still reads ' +
              'https:// (the status-list design note).',
          );
        }
        assertHttpsUrl(next.toString(), 'status list redirect target');
        url = next.toString();
        continue;
      }
      break;
    }

    if (response.status !== 200) {
      throw new StatusListResolutionError(
        'http-error',
        `refusing to verify against a status list that returned HTTP ${response.status}. Note that ` +
          'this FAILS the verification closed rather than treating an unavailable list as "nobody is ' +
          'revoked".',
      );
    }
    if (response.body.length > this.#maxBytes) {
      throw new StatusListResolutionError(
        'response-too-large',
        `refusing a ${response.body.length}-byte status list response, past the ${this.#maxBytes}-byte ` +
          'cap',
      );
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(
        Buffer.from(response.body.buffer, response.body.byteOffset, response.body.byteLength).toString(
          'utf8',
        ),
      );
    } catch (cause) {
      throw new StatusListResolutionError(
        'malformed',
        `refusing a status list document from ${url} that is not valid JSON`,
        { cause },
      );
    }

    let document: StatusListCredentialDocument;
    try {
      document = verifyStatusListCredential(parsed, {
        publicKeyRaw: pinned.publicKeyRaw,
        issuer: pinned.documentIssuer,
        ...(pinned.verificationMethod === undefined
          ? {}
          : { verificationMethod: pinned.verificationMethod }),
      });
    } catch (cause) {
      throw new StatusListResolutionError(
        'proof-invalid',
        `refusing a status list from ${url} whose own proof did not verify against the pinned issuer ` +
          `key: ${cause instanceof Error ? cause.message : String(cause)}`,
        { cause },
      );
    }

    const validFromSeconds = parseXsdDateTime(document.validFrom, 'validFrom');
    const validUntilSeconds = parseXsdDateTime(document.validUntil, 'validUntil');
    if (validUntilSeconds <= validFromSeconds) {
      throw new StatusListResolutionError(
        'malformed',
        `refusing a status list whose validUntil is not after its validFrom`,
      );
    }
    const list = toBitstringStatusList(document);
    // DECODED HERE, at resolution time, so a structurally broken bitstring fails as a RESOLUTION
    // failure with a useful message rather than surfacing later as an opaque `status-list-invalid`.
    // identity's decoder owns the multibase/base64url/gzip/16 KB-floor/statusMessage rules; running it
    // twice (once here, once inside verifyDetailed) costs one gunzip of a 16 KB buffer.
    await decodeStatusList(list, { expectedPurpose: list.statusPurpose as StatusPurpose });
    return { document, list, validFromSeconds, validUntilSeconds, fetchedAtSeconds: now };
  }

  /**
   * The three temporal checks, which are three DIFFERENT questions and are all needed:
   *
   *   validFrom  — is the document claiming to describe the future? (a clock-skew or a staged publish)
   *   validUntil — has the ISSUER stopped vouching for it?
   *   maxAge     — has the VERIFIER stopped believing it, independently of the issuer?
   */
  #assertTemporallyUsable(entry: CacheEntry, now: number, pinned: PinnedStatusListIssuer): void {
    if (now + 60 < entry.validFromSeconds) {
      throw new StatusListResolutionError(
        'not-yet-valid',
        `refusing a status list from ${pinned.url} whose validFrom is ` +
          `${entry.validFromSeconds - now}s in the future; either a clock is wrong or a staged ` +
          'document was published early, and reading revocation bits out of either is guesswork',
      );
    }
    if (now >= entry.validUntilSeconds) {
      throw new StatusListResolutionError(
        'expired',
        `refusing an EXPIRED status list from ${pinned.url} (validUntil was ` +
          `${now - entry.validUntilSeconds}s ago). Reading a stale bit out of an expired list is ` +
          'exactly what an attacker replaying an old document wants, so this fails the verification ' +
          'closed instead.',
      );
    }
    const documentAge = now - entry.validFromSeconds;
    if (documentAge > this.#maxAge) {
      throw new StatusListResolutionError(
        'stale',
        `refusing a status list from ${pinned.url} that is ${documentAge}s old, past this verifier's ` +
          `own ${this.#maxAge}s freshness bound (the issuer's validUntil would still have allowed ` +
          `it for another ${entry.validUntilSeconds - now}s). This bound is INDEPENDENT of validUntil ` +
          'on purpose: it is what lets a relying party be stricter than the issuer and is the only ' +
          'closure for the revocation window in the status-list design note.',
      );
    }
  }

  #assertPurpose(list: BitstringStatusList, wanted: StatusPurpose, url: string): void {
    if (list.statusPurpose !== wanted) {
      throw new StatusListResolutionError(
        'purpose-mismatch',
        `refusing to answer a "${wanted}" question from a "${String(list.statusPurpose)}" list ` +
          `at ${url}; reading a suspension bit as a revocation bit (or the reverse) is a wrong ` +
          'answer delivered confidently',
      );
    }
  }

  /** Drop cached documents. For an operator responding to an emergency revocation. */
  invalidate(): void {
    this.#cache.clear();
  }
}
