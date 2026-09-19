/**
 * K5, the PUBLISHER half, plus the shared HTTPS-only URL check.
 *
 * THE PUBLISHER MUST EMIT A LIST ITS OWN DECODER ACCEPTS. identity's decoder is strict in four ways a
 * naive publisher gets wrong, and all four are handled by delegating the bitstring entirely to
 * `encodeStatusList` — the same code path `decodeStatusList` inverts. Each of the four has a test.
 */

import { MINIMUM_STATUS_LIST_ENTRIES, decodeStatusList } from '@stellaronramp/identity';
import { describe, expect, it } from 'vitest';

import {
  DEFAULT_STATUS_LIST_VALIDITY_SECONDS,
  assertHttpsUrl,
  publishStatusList,
} from '../../src/status/publisher.js';
import {
  BITSTRING_STATUS_LIST_CREDENTIAL_TYPE,
  BITSTRING_STATUS_LIST_TYPE,
  STATUS_LIST_CRYPTOSUITE,
  StatusCredentialError,
  VC_V2_CONTEXT,
  toBitstringStatusList,
} from '../../src/status/credential.js';
import { ISSUER_SEED, LIST_URL, VERIFICATION_METHOD, publish } from './fixtures.js';

const VALID_FROM = 1_800_000_000;

describe('the published document is a well-formed BitstringStatusListCredential', () => {
  it('carries the W3C VC v2 context, both types, and both validity bounds', async () => {
    const doc = await publish({ revoked: [42] });
    expect(doc['@context']).toEqual([VC_V2_CONTEXT]);
    expect(doc.type).toEqual(['VerifiableCredential', BITSTRING_STATUS_LIST_CREDENTIAL_TYPE]);
    expect(doc.credentialSubject.type).toBe(BITSTRING_STATUS_LIST_TYPE);
    expect(doc.id).toBe(LIST_URL);
    expect(doc.credentialSubject.id).toBe(`${LIST_URL}#list`);
    expect(doc.validFrom).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);
    expect(doc.validUntil).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);
  });

  it('is SIGNED, with our named cryptosuite and an assertionMethod purpose', async () => {
    const doc = await publish({ revoked: [] });
    expect(doc.proof).toBeDefined();
    expect(doc.proof?.type).toBe('DataIntegrityProof');
    expect(doc.proof?.cryptosuite).toBe(STATUS_LIST_CRYPTOSUITE);
    expect(doc.proof?.proofPurpose).toBe('assertionMethod');
    expect(doc.proof?.verificationMethod).toBe(VERIFICATION_METHOD);
    // Multibase `u` + base64url of a 64-byte Ed25519 signature.
    expect(doc.proof?.proofValue).toMatch(/^u[A-Za-z0-9_-]{86}$/);
  });

  it('defaults validUntil to 24 h after validFrom, the issuer bound', async () => {
    expect(DEFAULT_STATUS_LIST_VALIDITY_SECONDS).toBe(86_400);
    const doc = await publish({ revoked: [], validFromSeconds: VALID_FROM });
    const from = Date.parse(doc.validFrom) / 1000;
    const until = Date.parse(doc.validUntil) / 1000;
    expect(until - from).toBe(DEFAULT_STATUS_LIST_VALIDITY_SECONDS);
  });

  it('honours an explicit validUntil', async () => {
    const doc = await publish({
      revoked: [],
      validFromSeconds: VALID_FROM,
      validUntilSeconds: VALID_FROM + 600,
    });
    expect(Date.parse(doc.validUntil) / 1000 - VALID_FROM).toBe(600);
  });
});

describe('THE FOUR WAYS identity\'s decoder is strict, all four honoured by DELEGATION', () => {
  /**
   * (1) A SHORT LIST IS REJECTED, NOT PADDED. 131,072 entries is a PRIVACY floor, not a formatting
   * nit — with a hundred-entry list, "the credential at index 42 of this list" is close to a name.
   * Padding a short list would MANUFACTURE the anonymity set the issuer failed to provide.
   */
  it.each([1, 100, 1_000, MINIMUM_STATUS_LIST_ENTRIES - 1, MINIMUM_STATUS_LIST_ENTRIES - 8])(
    'refuses to publish a %s-entry list, because the floor is a PRIVACY property',
    async (entries) => {
      await expect(publish({ revoked: [], entries })).rejects.toThrow();
    },
  );

  it('publishes at exactly the floor, and above it', async () => {
    await expect(
      publish({ revoked: [], entries: MINIMUM_STATUS_LIST_ENTRIES }),
    ).resolves.toBeDefined();
    await expect(
      publish({ revoked: [], entries: MINIMUM_STATUS_LIST_ENTRIES * 2 }),
    ).resolves.toBeDefined();
  });

  /** (2) AN UNKNOWN statusPurpose IS REJECTED, NOT READ AS "NOT REVOKED". */
  it.each(['refresh', 'message', 'REVOCATION', '', 'revoked'])(
    'refuses statusPurpose "%s" at publish time rather than at every verifier',
    async (statusPurpose) => {
      await expect(
        publish({ revoked: [], statusPurpose: statusPurpose as 'revocation' }),
      ).rejects.toThrow();
    },
  );

  it('publishes both known purposes', async () => {
    for (const statusPurpose of ['revocation', 'suspension'] as const) {
      const doc = await publish({ revoked: [1], statusPurpose });
      expect(doc.credentialSubject.statusPurpose).toBe(statusPurpose);
    }
  });

  /** (3) statusMessage IS ENFORCED per W3C §2.2 whenever statusSize > 1. */
  it('emits the statusMessage array identity requires when statusSize > 1', async () => {
    const doc = await publish({ revoked: [3], statusSize: 2 });
    expect(doc.credentialSubject.statusSize).toBe(2);
    expect(Array.isArray(doc.credentialSubject.statusMessage)).toBe(true);
    // And identity's own decoder accepts it — the round trip that proves §2.2 is satisfied.
    await expect(
      decodeStatusList(toBitstringStatusList(doc), { expectedPurpose: 'revocation' }),
    ).resolves.toBeDefined();
  });

  it('omits statusSize and statusMessage entirely for the 1-bit case', async () => {
    const doc = await publish({ revoked: [3] });
    expect('statusSize' in doc.credentialSubject).toBe(false);
    expect('statusMessage' in doc.credentialSubject).toBe(false);
  });

  /** (4) GZIP -> BASE64URL -> MULTIBASE, in that order, so the encoder must compress FIRST. */
  it('emits a multibase-u, base64url, GZIPPED bitstring that identity decodes', async () => {
    const doc = await publish({ revoked: [7] });
    expect(doc.credentialSubject.encodedList.startsWith('u')).toBe(true);
    const decoded = await decodeStatusList(toBitstringStatusList(doc), {
      expectedPurpose: 'revocation',
    });
    expect(decoded).toBeDefined();
  });

  /** THE DELIVERABLE PROPERTY: our publisher emits a list OUR OWN DECODER accepts. */
  it('every published list round-trips through identity\'s decodeStatusList', async () => {
    for (const revoked of [[], [0], [42], [131_071], [1, 2, 3, 999, 65_535]]) {
      const doc = await publish({ revoked });
      await expect(
        decodeStatusList(toBitstringStatusList(doc), { expectedPurpose: 'revocation' }),
        `revoked=[${revoked.join(',')}]`,
      ).resolves.toBeDefined();
    }
  });
});

describe('the publisher refuses a configuration that cannot be right', () => {
  /**
   * HTTPS IS ENFORCED ON THE PUBLISHED `id` TOO, not just on the fetch. The id is what a credential's
   * credentialStatus.statusListCredential points at, so an http: id would be BAKED INTO every
   * credentials that name a plaintext URL.
   */
  it.each([
    'http://status.example/list',
    'file:///etc/passwd',
    'data:application/json,{}',
    'blob:https://x/y',
    'ftp://status.example/list',
    '//status.example/list',
    'status.example/list',
    '',
    'https://user:pass@status.example/list',
    'https://user@status.example/list',
  ])('refuses to publish with id "%s"', async (url) => {
    await expect(publish({ revoked: [], url })).rejects.toThrow(StatusCredentialError);
  });

  it('refuses an empty issuer or verificationMethod', async () => {
    await expect(publish({ revoked: [], issuer: '' })).rejects.toThrow(/no issuer/);
    await expect(publish({ revoked: [], verificationMethod: '' })).rejects.toThrow(
      /no verificationMethod/,
    );
  });

  it.each([
    ['an inverted window', VALID_FROM, VALID_FROM - 1],
    ['a zero-length window', VALID_FROM, VALID_FROM],
  ])('refuses %s, which is a list expired the instant it is served', async (_l, from, until) => {
    await expect(
      publish({ revoked: [], validFromSeconds: from, validUntilSeconds: until }),
    ).rejects.toThrow(/not strictly after/);
  });

  it.each([-1, 1.5, Number.NaN])('refuses validFrom %s', async (validFromSeconds) => {
    await expect(publish({ revoked: [], validFromSeconds })).rejects.toThrow(StatusCredentialError);
  });

  it.each([-1, 1.5, Number.NaN, '42', null])(
    'refuses a revoked index of %s, which would silently set NO bit (i.e. fail to revoke someone)',
    async (index) => {
      await expect(publish({ revoked: [index as number] })).rejects.toThrow();
    },
  );

  it('refuses an index outside the list, rather than silently dropping the revocation', async () => {
    await expect(
      publish({ revoked: [MINIMUM_STATUS_LIST_ENTRIES], entries: MINIMUM_STATUS_LIST_ENTRIES }),
    ).rejects.toThrow();
  });

  it('refuses a signing key that is not a 32-byte seed', async () => {
    for (const seed of [new Uint8Array(31), new Uint8Array(33), new Uint8Array(0)]) {
      await expect(publish({ revoked: [], signingKey: { seed } })).rejects.toThrow(
        StatusCredentialError,
      );
    }
  });

  it('accepts the boundary indices 0 and entries-1', async () => {
    await expect(publish({ revoked: [0] })).resolves.toBeDefined();
    await expect(publish({ revoked: [MINIMUM_STATUS_LIST_ENTRIES - 1] })).resolves.toBeDefined();
  });
});

describe('assertHttpsUrl: HTTPS ONLY, and new URL() not a regex', () => {
  it('accepts a plain https URL and normalises the scheme case', () => {
    expect(assertHttpsUrl('https://status.example/list').protocol).toBe('https:');
    expect(assertHttpsUrl('HTTPS://status.example/list').protocol).toBe('https:');
  });

  /**
   * A regex over URLs is how `https://evil.com\@good.com` gets through. `new URL()` parses the
   * authority properly, which is why it is used.
   */
  it.each([
    ['plain http', 'http://status.example/list'],
    ['file', 'file:///etc/passwd'],
    ['data', 'data:text/plain,x'],
    ['blob', 'blob:https://x/y'],
    ['ftp', 'ftp://x/y'],
    ['javascript', 'javascript:alert(1)'],
    ['a protocol-relative URL', '//status.example/list'],
    ['a bare host', 'status.example/list'],
    ['a relative path', '/list'],
    ['an empty string', ''],
    ['embedded credentials', 'https://user:pass@status.example/list'],
    ['a username only', 'https://user@status.example/list'],
  ])('refuses %s', (_label, url) => {
    expect(() => assertHttpsUrl(url)).toThrow(StatusCredentialError);
  });

  /**
   * A LIMIT I FOUND BY WRITING THIS TEST, recorded rather than quietly deleted.
   *
   * `assertHttpsUrl` is a SCHEME check and a credentials-in-authority check. It is NOT a host check,
   * and it cannot be: WHATWG `URL` normalises backslashes to forward slashes for special schemes, so
   * `https:/\/\evil.example` really is a well-formed `https://evil.example/` and this function accepts
   * it — correctly, because it IS an HTTPS URL.
   *
   * WHY THAT IS SAFE HERE, and it is worth being explicit because "the URL check passed" is easy to
   * over-read. The resolver never fetches a caller-supplied URL: it fetches `pinned.url` from its own
   * configuration, and every redirect target must additionally produce a document whose Ed25519 proof
   * verifies against the PINNED key. So a hostile host reached by any URL trick still cannot serve a
   * list we will believe. Host allowlisting would be defence in depth, but the SIGNATURE is the
   */
  it('is a SCHEME check, not a HOST check: a backslash-normalised https URL is accepted', () => {
    const url = assertHttpsUrl('https:/\\/\\evil.example');
    expect(url.protocol).toBe('https:');
    expect(url.hostname).toBe('evil.example');
    // The pinned key, not this function, is what stops that host being believed.
  });

  it.each([null, undefined, 42, {}, []])('refuses a non-string URL: %s', (url) => {
    expect(() => assertHttpsUrl(url)).toThrow(StatusCredentialError);
  });

  it('names the MITM consequence in its message, so the reason survives a refactor', () => {
    let caught: Error | undefined;
    try {
      assertHttpsUrl('http://status.example/list');
    } catch (e) {
      caught = e as Error;
    }
    expect(caught?.message).toContain('UN-REVOKE EVERY HOLDER');
  });

  it('carries the caller-supplied label so an operator knows WHICH url was refused', () => {
    expect(() => assertHttpsUrl('http://x/y', 'pinned status list URL')).toThrow(
      /pinned status list URL/,
    );
  });
});

describe('the signing key is used but never emitted', () => {
  it('the published document contains no private key material', async () => {
    const doc = await publish({ revoked: [1] });
    const serialised = JSON.stringify(doc);
    expect(serialised).not.toContain(Buffer.from(ISSUER_SEED).toString('base64'));
    expect(serialised).not.toContain(Buffer.from(ISSUER_SEED).toString('hex'));
    expect(serialised).not.toContain('privateKey');
    expect(serialised).not.toContain('seed');
  });
});
