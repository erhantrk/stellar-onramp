/**
 * THE HARDENED DEREFERENCER. K5's first half, and the thing nothing in this repo has ever had.
 *
 * AN MITM WHO CAN UN-REVOKE ANYBODY" and "a caller who caches a list for a week has a week-long
 * revocation window". Every control below closes one of those, and each has its own test as the brief
 * required.
 *
 * NO NETWORK. Every test injects `FakeStatusListHttp`. `FetchStatusListHttp` is never constructed.
 */

import { MAX_STATUS_LIST_BYTES } from '@stellaronramp/identity';
import type { StatusListRequest } from '@stellaronramp/identity';
import { describe, expect, it } from 'vitest';

import {
  DEFAULT_STATUS_LIST_CACHE_TTL_SECONDS,
  DEFAULT_STATUS_LIST_MAX_AGE_SECONDS,
  DEFAULT_STATUS_LIST_TIMEOUT_MS,
  HardenedStatusListResolver,
  MAX_STATUS_LIST_REDIRECTS,
  StatusListResolutionError,
} from '../../src/status/resolver.js';
import type { HardenedStatusListResolverConfig } from '../../src/status/resolver.js';
import { signStatusListCredential, STATUS_LIST_CRYPTOSUITE } from '../../src/status/credential.js';
import {
  DEFAULT_VALID_FROM,
  DOCUMENT_ISSUER,
  FakeStatusListHttp,
  ISSUER_ID,
  ISSUER_PUBLIC_KEY,
  LIST_URL,
  OTHER_PUBLIC_KEY,
  OTHER_SEED,
  VERIFICATION_METHOD,
  publish,
} from './fixtures.js';

const REQUEST: StatusListRequest = {
  revocationIndex: 42,
  issuerId: ISSUER_ID,
  statusPurpose: 'revocation',
};

function makeResolver(
  http: FakeStatusListHttp,
  over: Partial<HardenedStatusListResolverConfig> = {},
  now = DEFAULT_VALID_FROM,
): HardenedStatusListResolver {
  return new HardenedStatusListResolver({
    issuers: [
      {
        issuerId: ISSUER_ID,
        url: LIST_URL,
        publicKeyRaw: ISSUER_PUBLIC_KEY,
        documentIssuer: DOCUMENT_ISSUER,
        verificationMethod: VERIFICATION_METHOD,
      },
    ],
    http,
    now: () => now,
    ...over,
  });
}

async function expectReason(fn: () => Promise<unknown>, reason: string): Promise<Error> {
  let caught: unknown;
  try {
    await fn();
  } catch (e) {
    caught = e;
  }
  expect(caught, `expected a StatusListResolutionError(${reason}), got none`).toBeInstanceOf(
    StatusListResolutionError,
  );
  expect((caught as StatusListResolutionError).reason).toBe(reason);
  return caught as Error;
}

describe('the happy path, so every failure test below is a real contrast', () => {
  it('fetches, verifies the proof, checks the clock and returns the list', async () => {
    const http = new FakeStatusListHttp({ document: await publish({ revoked: [42] }) });
    const list = await makeResolver(http).resolve(REQUEST);
    expect(list.statusPurpose).toBe('revocation');
    expect(list.encodedList.startsWith('u')).toBe(true);
    expect(http.urls).toEqual([LIST_URL]);
  });

  it('exposes the exact function type VerifyOptions.statusList accepts', async () => {
    const http = new FakeStatusListHttp({ document: await publish({ revoked: [] }) });
    const fn = makeResolver(http).asStatusListResolver();
    expect(typeof fn).toBe('function');
    await expect(fn(REQUEST)).resolves.toBeDefined();
  });
});

describe('CONTROL: HTTPS ONLY. This is the MITM-un-revokes-anybody hole.', () => {
  it.each([
    ['http', 'http://status.example/list'],
    ['file', 'file:///etc/passwd'],
    ['data', 'data:application/json,{}'],
    ['blob', 'blob:https://x/y'],
    ['a protocol-relative //host URL', '//status.example/list'],
    ['ftp', 'ftp://status.example/list'],
  ])('refuses to even CONSTRUCT a resolver pinned to a %s URL', (_label, url) => {
    expect(
      () =>
        new HardenedStatusListResolver({
          issuers: [
            {
              issuerId: ISSUER_ID,
              url,
              publicKeyRaw: ISSUER_PUBLIC_KEY,
              documentIssuer: DOCUMENT_ISSUER,
            },
          ],
          http: new FakeStatusListHttp({ status: 200 }),
          now: () => DEFAULT_VALID_FROM,
        }),
    ).toThrow();
  });

  /**
   * THE DOWNGRADE. An `https://` URL that 302s to `http://` LOOKS secure in the config and is a
   * plaintext fetch on the wire. This is why the resolver follows redirects ITSELF.
   */
  it.each([
    ['http', 'http://status.example/list'],
    ['a relative Location that resolves to http via a full URL', 'http://status.example/other'],
    ['file', 'file:///etc/passwd'],
    ['data', 'data:application/json,{}'],
    ['ftp', 'ftp://status.example/l'],
  ])('refuses a redirect that downgrades to %s', async (_label, location) => {
    const http = new FakeStatusListHttp([{ status: 302, headers: { location } }]);
    const err = await expectReason(() => makeResolver(http).resolve(REQUEST), 'redirect-downgrade');
    expect(err.message).toContain('un-revoke every holder');
  });

  it('FOLLOWS an https->https redirect itself, so every hop is re-checked', async () => {
    const doc = await publish({ revoked: [42] });
    const http = new FakeStatusListHttp([
      { status: 302, headers: { location: 'https://cdn.example/mirror' } },
      { document: doc },
    ]);
    await expect(makeResolver(http).resolve(REQUEST)).resolves.toBeDefined();
    // Two URLs recorded is the proof the RESOLVER followed the redirect, not the transport.
    expect(http.urls).toEqual([LIST_URL, 'https://cdn.example/mirror']);
  });

  it('resolves a RELATIVE Location against the current URL and re-checks the result', async () => {
    const doc = await publish({ revoked: [42] });
    const http = new FakeStatusListHttp([
      { status: 302, headers: { location: '/v1/mirror' } },
      { document: doc },
    ]);
    await expect(makeResolver(http).resolve(REQUEST)).resolves.toBeDefined();
    expect(http.urls[1]).toBe('https://status.stellaronramp.example/v1/mirror');
  });

  it('refuses a redirect with no Location header', async () => {
    const http = new FakeStatusListHttp([{ status: 302, headers: {} }]);
    await expectReason(() => makeResolver(http).resolve(REQUEST), 'malformed');
  });

  /**
   * Finding a Location that `new URL(location, base)` really rejects takes care, because WHATWG URL is
   * extremely lenient once a base is supplied: `ht!tp://%%%` parses as a RELATIVE path against the base
   * and comes out as `https://status.stellaronramp.example/...`, which is why it is in the second list
   * below rather than this one. These four are genuinely unparseable (invalid host / bracket / space).
   */
  it.each(['https://[', 'http://[::1', 'https://exa mple', 'https://%'])(
    'refuses a redirect whose Location "%s" is not a URL at all',
    async (location) => {
      const http = new FakeStatusListHttp([{ status: 302, headers: { location } }]);
      await expectReason(() => makeResolver(http).resolve(REQUEST), 'malformed');
    },
  );

  it('a Location with an invalid SCHEME is treated as RELATIVE and stays on the pinned origin', async () => {
    // `ht!tp://%%%` is not a scheme (`!` is illegal), so WHATWG resolves it as a relative reference.
    // The result is still https and still on the pinned host, so it is followed — and then has to
    // produce a document that verifies against the pinned key. Recorded because "it looked like a
    // scheme" is exactly the kind of thing a reader assumes is rejected.
    const doc = await publish({ revoked: [42] });
    const http = new FakeStatusListHttp([
      { status: 302, headers: { location: 'ht!tp://%%%' } },
      { document: doc },
    ]);
    await expect(makeResolver(http).resolve(REQUEST)).resolves.toBeDefined();
    expect(new URL(http.urls[1]!).protocol).toBe('https:');
    expect(new URL(http.urls[1]!).hostname).toBe('status.stellaronramp.example');
  });
});

describe('CONTROL: the list VERIFIES ITS OWN SIGNATURE against a PINNED key', () => {
  it('refuses an UNSIGNED list: anyone who can write to the bucket could un-revoke everyone', async () => {
    const doc = await publish({ revoked: [42] });
    const { proof: _dropped, ...unsigned } = doc;
    void _dropped;
    const http = new FakeStatusListHttp({ document: unsigned });
    const err = await expectReason(() => makeResolver(http).resolve(REQUEST), 'proof-invalid');
    expect(err.message).toContain('UNSIGNED');
  });

  /** Correctly signed, by the WRONG KEY. Every forgery is internally self-consistent. */
  it('refuses a list signed by a DIFFERENT issuer key, however well-formed', async () => {
    const forged = await publish({ revoked: [], signingKey: { seed: OTHER_SEED } });
    const http = new FakeStatusListHttp({ document: forged });
    await expectReason(() => makeResolver(http).resolve(REQUEST), 'proof-invalid');
    // Sanity: it WOULD verify against the other key, so the document itself is valid.
    const other = makeResolver(new FakeStatusListHttp({ document: forged }), {
      issuers: [
        {
          issuerId: ISSUER_ID,
          url: LIST_URL,
          publicKeyRaw: OTHER_PUBLIC_KEY,
          documentIssuer: DOCUMENT_ISSUER,
          verificationMethod: VERIFICATION_METHOD,
        },
      ],
    });
    await expect(other.resolve(REQUEST)).resolves.toBeDefined();
  });

  /** THE ATTACK THE SIGNATURE EXISTS FOR: swap the bitstring for an all-zero one. */
  it('refuses a list whose encodedList was SWAPPED for an all-clear one after signing', async () => {
    const revokedDoc = await publish({ revoked: [42] });
    const clearDoc = await publish({ revoked: [] });
    const tampered = {
      ...revokedDoc,
      credentialSubject: {
        ...revokedDoc.credentialSubject,
        encodedList: clearDoc.credentialSubject.encodedList,
      },
    };
    const http = new FakeStatusListHttp({ document: tampered });
    await expectReason(() => makeResolver(http).resolve(REQUEST), 'proof-invalid');
  });

  it.each([
    ['validUntil', 'validUntil'],
    ['validFrom', 'validFrom'],
    ['id', 'id'],
    ['issuer', 'issuer'],
  ])('refuses a list whose %s was altered after signing', async (_label, field) => {
    const doc = await publish({ revoked: [42] });
    const tampered = { ...doc, [field]: field.startsWith('valid') ? '2030-01-01T00:00:00Z' : 'x' };
    const http = new FakeStatusListHttp({ document: tampered });
    await expectReason(() => makeResolver(http).resolve(REQUEST), 'proof-invalid');
  });

  /**
   * THE PROOF CONFIG IS SIGNED TOO. Without that, an attacker holding one valid signature could
   * re-present it under a different cryptosuite or verificationMethod label — the same bug class as
   * dispatching on X-Payload-Digest-Alg, one layer up.
   */
  it('refuses a re-labelled proof: cryptosuite and verificationMethod are COMMITTED TO', async () => {
    const doc = await publish({ revoked: [42] });
    for (const field of ['cryptosuite', 'verificationMethod', 'created', 'proofPurpose'] as const) {
      const tampered = {
        ...doc,
        proof: { ...doc.proof!, [field]: field === 'created' ? '2030-01-01T00:00:00Z' : 'relabelled' },
      };
      await expectReason(
        () => makeResolver(new FakeStatusListHttp({ document: tampered })).resolve(REQUEST),
        'proof-invalid',
      );
    }
  });

  it('pins the cryptosuite SERVER-SIDE: a document does not get to choose which suite verifies it', async () => {
    const doc = await publish({ revoked: [42] });
    // Re-sign properly under a DIFFERENT suite name; the signature is internally valid.
    const { proof: _p, ...unsigned } = doc;
    void _p;
    const reSigned = signStatusListCredential(
      unsigned as typeof doc,
      { seed: Uint8Array.from({ length: 32 }, (_, i) => i + 1) },
      {
        type: 'DataIntegrityProof',
        cryptosuite: 'eddsa-jcs-2022',
        created: doc.proof!.created,
        verificationMethod: VERIFICATION_METHOD,
        proofPurpose: 'assertionMethod',
      },
    );
    expect(reSigned.proof?.cryptosuite).not.toBe(STATUS_LIST_CRYPTOSUITE);
    await expectReason(
      () => makeResolver(new FakeStatusListHttp({ document: reSigned })).resolve(REQUEST),
      'proof-invalid',
    );
  });

  it('refuses a wrong documentIssuer even when the signature verifies', async () => {
    const doc = await publish({ revoked: [42] });
    const resolver = makeResolver(new FakeStatusListHttp({ document: doc }), {
      issuers: [
        {
          issuerId: ISSUER_ID,
          url: LIST_URL,
          publicKeyRaw: ISSUER_PUBLIC_KEY,
          documentIssuer: 'did:web:someone-else.example',
        },
      ],
    });
    await expectReason(() => resolver.resolve(REQUEST), 'proof-invalid');
  });

  it('refuses to be pinned to a key that is not 32 raw bytes', () => {
    for (const publicKeyRaw of [new Uint8Array(31), new Uint8Array(33), new Uint8Array(0)]) {
      expect(
        () =>
          new HardenedStatusListResolver({
            issuers: [
              { issuerId: ISSUER_ID, url: LIST_URL, publicKeyRaw, documentIssuer: DOCUMENT_ISSUER },
            ],
            http: new FakeStatusListHttp({ status: 200 }),
            now: () => DEFAULT_VALID_FROM,
          }),
      ).toThrow(StatusListResolutionError);
    }
  });

  it('refuses to be built with NO pinned issuers at all', () => {
    expect(
      () =>
        new HardenedStatusListResolver({
          issuers: [],
          http: new FakeStatusListHttp({ status: 200 }),
          now: () => DEFAULT_VALID_FROM,
        }),
    ).toThrow(/no pinned issuers/);
  });

  it('refuses TWO pinned configs for one issuer: the later would silently win', () => {
    const one = {
      issuerId: ISSUER_ID,
      url: LIST_URL,
      publicKeyRaw: ISSUER_PUBLIC_KEY,
      documentIssuer: DOCUMENT_ISSUER,
    };
    expect(
      () =>
        new HardenedStatusListResolver({
          issuers: [one, { ...one, publicKeyRaw: OTHER_PUBLIC_KEY }],
          http: new FakeStatusListHttp({ status: 200 }),
          now: () => DEFAULT_VALID_FROM,
        }),
    ).toThrow(/two pinned configurations/);
  });
});

describe('CONTROL: validFrom / validUntil, and an EXPIRED list is REFUSED not read', () => {
  it('refuses an EXPIRED list rather than reading a stale bit out of it', async () => {
    const doc = await publish({
      revoked: [42],
      validFromSeconds: DEFAULT_VALID_FROM,
      validUntilSeconds: DEFAULT_VALID_FROM + 3600,
    });
    const http = new FakeStatusListHttp({ document: doc });
    const err = await expectReason(
      () => makeResolver(http, {}, DEFAULT_VALID_FROM + 3601).resolve(REQUEST),
      'expired',
    );
    expect(err.message).toContain('EXPIRED');
  });

  it('accepts a list one second before its validUntil and refuses it one second after', async () => {
    const doc = await publish({
      revoked: [42],
      validUntilSeconds: DEFAULT_VALID_FROM + 3600,
    });
    await expect(
      makeResolver(
        new FakeStatusListHttp({ document: doc }),
        { maxAgeSeconds: 7200 },
        DEFAULT_VALID_FROM + 3599,
      ).resolve(REQUEST),
    ).resolves.toBeDefined();
    await expectReason(
      () =>
        makeResolver(
          new FakeStatusListHttp({ document: doc }),
          { maxAgeSeconds: 7200 },
          DEFAULT_VALID_FROM + 3600,
        ).resolve(REQUEST),
      'expired',
    );
  });

  it('refuses a NOT-YET-VALID list: a clock is wrong or a staged document was published early', async () => {
    const doc = await publish({ revoked: [42], validFromSeconds: DEFAULT_VALID_FROM + 100_000 });
    await expectReason(
      () => makeResolver(new FakeStatusListHttp({ document: doc })).resolve(REQUEST),
      'not-yet-valid',
    );
  });

  it('tolerates a small clock skew on validFrom', async () => {
    const doc = await publish({ revoked: [42], validFromSeconds: DEFAULT_VALID_FROM + 30 });
    await expect(
      makeResolver(new FakeStatusListHttp({ document: doc })).resolve(REQUEST),
    ).resolves.toBeDefined();
  });

  it.each([
    ['a missing validUntil', 'validUntil'],
    ['a missing validFrom', 'validFrom'],
    ['a missing id', 'id'],
    ['a missing issuer', 'issuer'],
  ])('refuses %s (checked BEFORE the signature, as a shape failure)', async (_label, field) => {
    const doc = await publish({ revoked: [42] });
    const stripped = { ...doc } as Record<string, unknown>;
    delete stripped[field];
    await expectReason(
      () => makeResolver(new FakeStatusListHttp({ document: stripped })).resolve(REQUEST),
      'proof-invalid',
    );
  });
});

describe('CONTROL: verifier-side FRESHNESS, INDEPENDENT of validUntil', () => {
  it('pins the defaults, and the cache TTL is inside the freshness bound', () => {
    expect(DEFAULT_STATUS_LIST_MAX_AGE_SECONDS).toBe(300);
    expect(DEFAULT_STATUS_LIST_CACHE_TTL_SECONDS).toBe(60);
    expect(DEFAULT_STATUS_LIST_CACHE_TTL_SECONDS).toBeLessThanOrEqual(
      DEFAULT_STATUS_LIST_MAX_AGE_SECONDS,
    );
  });

  /**
   * THE POINT OF THE WHOLE MODULE. The issuer's validUntil would still have allowed this document for
   * "a caller who caches a list for a week has a week-long revocation window".
   */
  it('refuses a STALE-but-UNEXPIRED list, i.e. is STRICTER than the issuer', async () => {
    const doc = await publish({
      revoked: [42],
      validFromSeconds: DEFAULT_VALID_FROM,
      validUntilSeconds: DEFAULT_VALID_FROM + 86_400, // the issuer says: fine for 24 h
    });
    const now = DEFAULT_VALID_FROM + 600; // 10 minutes old; the verifier's bound is 5
    const err = await expectReason(
      () => makeResolver(new FakeStatusListHttp({ document: doc }), {}, now).resolve(REQUEST),
      'stale',
    );
    expect(err.message).toContain("validUntil would still have allowed");
    expect(err.message).toContain('INDEPENDENT of validUntil');
  });

  it('measures the age from validFrom, NOT from the fetch, so a mirror cannot serve it forever', async () => {
    // If age were measured from the fetch, re-fetching an ancient document would make it "fresh".
    const doc = await publish({ revoked: [42], validUntilSeconds: DEFAULT_VALID_FROM + 86_400 });
    const old = DEFAULT_VALID_FROM + 10_000;
    for (const attempt of [1, 2, 3]) {
      await expectReason(
        () =>
          makeResolver(new FakeStatusListHttp({ document: doc }), {}, old).resolve(REQUEST),
        'stale',
      );
      expect(attempt).toBeGreaterThan(0);
    }
  });

  it('accepts a document just inside the bound and refuses one just outside', async () => {
    const doc = await publish({ revoked: [42], validUntilSeconds: DEFAULT_VALID_FROM + 86_400 });
    await expect(
      makeResolver(new FakeStatusListHttp({ document: doc }), {}, DEFAULT_VALID_FROM + 300).resolve(
        REQUEST,
      ),
    ).resolves.toBeDefined();
    await expectReason(
      () =>
        makeResolver(new FakeStatusListHttp({ document: doc }), {}, DEFAULT_VALID_FROM + 301).resolve(
          REQUEST,
        ),
      'stale',
    );
  });

  it('lets a caller be STRICTER still', async () => {
    const doc = await publish({ revoked: [42] });
    await expectReason(
      () =>
        makeResolver(
          new FakeStatusListHttp({ document: doc }),
          { maxAgeSeconds: 10, cacheTtlSeconds: 5 },
          DEFAULT_VALID_FROM + 11,
        ).resolve(REQUEST),
      'stale',
    );
  });

  it.each([0, -1, Number.POSITIVE_INFINITY, Number.NaN])(
    'refuses a freshness bound of %s, which is the same as NO bound',
    (maxAgeSeconds) => {
      expect(() =>
        makeResolver(new FakeStatusListHttp({ status: 200 }), {
          maxAgeSeconds,
          cacheTtlSeconds: 0,
        }),
      ).toThrow(StatusListResolutionError);
    },
  );

  it('refuses a cache TTL LONGER than the freshness bound', async () => {
    // A cache that outlives the freshness bound serves documents it would refuse to fetch.
    expect(() =>
      makeResolver(new FakeStatusListHttp({ status: 200 }), {
        maxAgeSeconds: 60,
        cacheTtlSeconds: 61,
      }),
    ).toThrow(/longer than the freshness bound/);
  });
});

describe('CONTROL: caching, with an ANSWERABLE age', () => {
  it('serves a second resolution from cache without a second fetch', async () => {
    const http = new FakeStatusListHttp({ document: await publish({ revoked: [42] }) });
    const resolver = makeResolver(http);
    await resolver.resolve(REQUEST);
    await resolver.resolve(REQUEST);
    expect(http.callCount).toBe(1);
    expect(resolver.lastProvenance?.fromCache).toBe(true);
  });

  it('a caller can ask HOW OLD the bit it is about to trust is', async () => {
    const doc = await publish({ revoked: [42], validUntilSeconds: DEFAULT_VALID_FROM + 86_400 });
    const resolver = makeResolver(
      new FakeStatusListHttp({ document: doc }),
      {},
      DEFAULT_VALID_FROM + 120,
    );
    expect(resolver.lastProvenance).toBeUndefined();
    await resolver.resolve(REQUEST);
    expect(resolver.lastProvenance).toEqual({
      url: LIST_URL,
      issuerId: ISSUER_ID,
      documentAgeSeconds: 120,
      cacheAgeSeconds: 0,
      maxAgeSeconds: DEFAULT_STATUS_LIST_MAX_AGE_SECONDS,
      validUntilSeconds: DEFAULT_VALID_FROM + 86_400,
      fromCache: false,
    });
  });

  /**
   * TIME-OF-CHECK / TIME-OF-USE. A cached document may have EXPIRED or gone STALE while it sat in the
   * cache, and serving it because "we already validated it" is exactly the bug.
   */
  it('RE-CHECKS the clock on a cache HIT, so a cached document cannot outlive its validity', async () => {
    let now = DEFAULT_VALID_FROM;
    const doc = await publish({
      revoked: [42],
      validUntilSeconds: DEFAULT_VALID_FROM + 30,
    });
    const http = new FakeStatusListHttp({ document: doc }, true);
    const resolver = new HardenedStatusListResolver({
      issuers: [
        {
          issuerId: ISSUER_ID,
          url: LIST_URL,
          publicKeyRaw: ISSUER_PUBLIC_KEY,
          documentIssuer: DOCUMENT_ISSUER,
        },
      ],
      http,
      now: () => now,
      maxAgeSeconds: 600,
      cacheTtlSeconds: 600,
    });
    await expect(resolver.resolve(REQUEST)).resolves.toBeDefined();
    // Still inside the 600 s cache TTL, but PAST the document's own 30 s validUntil.
    now = DEFAULT_VALID_FROM + 40;
    await expectReason(() => resolver.resolve(REQUEST), 'expired');
  });

  it('does NOT cache a document that failed a check: one bad response is not a sustained outage', async () => {
    const forged = await publish({ revoked: [], signingKey: { seed: OTHER_SEED } });
    const good = await publish({ revoked: [42] });
    const http = new FakeStatusListHttp([{ document: forged }, { document: good }]);
    const resolver = makeResolver(http);
    await expectReason(() => resolver.resolve(REQUEST), 'proof-invalid');
    // The next attempt re-fetches and succeeds rather than being poisoned for the whole TTL.
    await expect(resolver.resolve(REQUEST)).resolves.toBeDefined();
    expect(http.callCount).toBe(2);
  });

  it('invalidate() drops the cache, for an operator responding to an emergency revocation', async () => {
    const http = new FakeStatusListHttp({ document: await publish({ revoked: [42] }) }, true);
    const resolver = makeResolver(http);
    await resolver.resolve(REQUEST);
    expect(http.callCount).toBe(1);
    resolver.invalidate();
    await resolver.resolve(REQUEST);
    expect(http.callCount).toBe(2);
  });
});

describe('CONTROL: the fetch is BOUNDED — timeout, size cap, redirect cap', () => {
  it('passes identity\'s MAX_STATUS_LIST_BYTES down rather than inventing a cap', async () => {
    const http = new FakeStatusListHttp({ document: await publish({ revoked: [42] }) });
    await makeResolver(http).resolve(REQUEST);
    expect(http.options[0]).toEqual({
      timeoutMs: DEFAULT_STATUS_LIST_TIMEOUT_MS,
      maxBytes: MAX_STATUS_LIST_BYTES,
    });
    expect(MAX_STATUS_LIST_BYTES).toBe(16 * 1024 * 1024);
  });

  it('refuses a body over the cap even if the transport handed one over anyway', async () => {
    const http = new FakeStatusListHttp({ body: Buffer.alloc(1024), status: 200 });
    await expectReason(
      () => makeResolver(http, { maxBytes: 512 }).resolve(REQUEST),
      'response-too-large',
    );
  });

  it('classifies an AbortError as a TIMEOUT, naming the hung-verification hazard', async () => {
    const abort = Object.assign(new Error('aborted'), { name: 'AbortError' });
    const err = await expectReason(
      () => makeResolver(new FakeStatusListHttp({ throws: abort })).resolve(REQUEST),
      'timeout',
    );
    expect(err.message).toContain('never completes');
  });

  it('classifies any other transport failure as `transport`, and still fails CLOSED', async () => {
    await expectReason(
      () => makeResolver(new FakeStatusListHttp({ throws: new Error('ECONNREFUSED') })).resolve(REQUEST),
      'transport',
    );
  });

  it('caps redirects at 3 and refuses a redirect LOOP', async () => {
    expect(MAX_STATUS_LIST_REDIRECTS).toBe(3);
    const http = new FakeStatusListHttp(
      [{ status: 302, headers: { location: 'https://a.example/loop' } }],
      true,
    );
    await expectReason(() => makeResolver(http).resolve(REQUEST), 'too-many-redirects');
    expect(http.callCount).toBeLessThanOrEqual(MAX_STATUS_LIST_REDIRECTS + 1);
  });

  it('honours a stricter redirect cap', async () => {
    const http = new FakeStatusListHttp(
      [{ status: 302, headers: { location: 'https://a.example/loop' } }],
      true,
    );
    await expectReason(() => makeResolver(http, { maxRedirects: 1 }).resolve(REQUEST), 'too-many-redirects');
  });

  it.each([301, 302, 303, 307, 308])('treats HTTP %s as a redirect to be checked', async (status) => {
    const http = new FakeStatusListHttp([
      { status, headers: { location: 'http://downgrade.example/l' } },
    ]);
    await expectReason(() => makeResolver(http).resolve(REQUEST), 'redirect-downgrade');
  });
});

describe('FAIL CLOSED on every other failure shape', () => {
  it.each([404, 403, 500, 502, 503, 204, 418])(
    'refuses HTTP %s rather than treating an unavailable list as "nobody is revoked"',
    async (status) => {
      const err = await expectReason(
        () => makeResolver(new FakeStatusListHttp({ status, body: Buffer.from('x') })).resolve(REQUEST),
        'http-error',
      );
      expect(err.message).toContain('FAILS the verification closed');
    },
  );

  it.each([
    ['not JSON at all', 'this is not json'],
    ['an empty body', ''],
    ['a JSON array', '[]'],
    ['a JSON string', '"x"'],
    ['a JSON number', '42'],
    ['JSON null', 'null'],
    ['truncated JSON', '{"@context":['],
  ])('refuses a body that is %s', async (_label, body) => {
    const http = new FakeStatusListHttp({ body, status: 200 });
    let caught: unknown;
    try {
      await makeResolver(http).resolve(REQUEST);
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(StatusListResolutionError);
    expect(['malformed', 'proof-invalid']).toContain(
      (caught as StatusListResolutionError).reason,
    );
  });

  it('refuses a document that is not a BitstringStatusListCredential', async () => {
    const doc = await publish({ revoked: [42] });
    const wrongType = { ...doc, type: ['VerifiableCredential', 'SomethingElse'] };
    await expectReason(
      () => makeResolver(new FakeStatusListHttp({ document: wrongType })).resolve(REQUEST),
      'proof-invalid',
    );
  });

  it('refuses a document missing the W3C VC v2 context', async () => {
    const doc = await publish({ revoked: [42] });
    await expectReason(
      () =>
        makeResolver(new FakeStatusListHttp({ document: { ...doc, '@context': [] } })).resolve(
          REQUEST,
        ),
      'proof-invalid',
    );
  });

  /** Reading a SUSPENSION bit as a REVOCATION bit is a wrong answer delivered confidently. */
  it('refuses to answer a "revocation" question from a "suspension" list', async () => {
    const doc = await publish({ revoked: [42], statusPurpose: 'suspension' });
    await expectReason(
      () => makeResolver(new FakeStatusListHttp({ document: doc })).resolve(REQUEST),
      'purpose-mismatch',
    );
  });

  it('refuses an UNPINNED issuer rather than guessing', async () => {
    const http = new FakeStatusListHttp({ document: await publish({ revoked: [42] }) });
    await expectReason(
      () => makeResolver(http).resolve({ ...REQUEST, issuerId: 'c'.repeat(64) }),
      'unknown-issuer',
    );
    expect(http.callCount, 'an unpinned issuer must not cause a fetch').toBe(0);
  });

  /**
   * A proof that did not disclose claim index 1 has no issuerId. Defaulting to "whichever issuer we
   * happen to have configured first" is how a credential from issuer A gets its revocation status read
   * out of issuer B's list — an un-revoke for anyone A revoked.
   */
  it('refuses an UNDISCLOSED issuerId unless defaultIssuerId is set EXPLICITLY', async () => {
    const http = new FakeStatusListHttp({ document: await publish({ revoked: [42] }) }, true);
    await expectReason(
      () => makeResolver(http).resolve({ ...REQUEST, issuerId: undefined }),
      'issuer-undisclosed',
    );
    // With an explicit single-issuer default it resolves.
    const withDefault = makeResolver(http, { defaultIssuerId: ISSUER_ID });
    await expect(withDefault.resolve({ ...REQUEST, issuerId: undefined })).resolves.toBeDefined();
  });

  it('every rejection is a THROW; there is no code path that synthesises an empty list', async () => {
    // An all-zero 131,072-entry bitstring is a perfectly well-formed list that says nobody is
    // revoked. Returning one instead of throwing would silently un-revoke everyone.
    const source = await import('node:fs/promises').then((fs) =>
      fs.readFile(new URL('../../src/status/resolver.ts', import.meta.url), 'utf8'),
    );
    const code = source.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/^\s*\/\/.*$/gm, ' ');
    expect(code).not.toMatch(/encodeStatusList/);
    expect(code).not.toMatch(/return\s*\{\s*statusPurpose/);
  });
});
