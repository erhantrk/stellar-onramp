/**
 * THE DELIVERABLE. The brief: "publish a list with index N set, dereference it through your own
 * resolver, and confirm verifyDetailed returns valid:false with reason `revoked` for a credential at
 * index N and valid:true for one at index M. That round trip is the deliverable."
 *
 * This is the first time in this repo that a status list is PUBLISHED, FETCHED over a (faked) HTTPS
 * transport, has its OWN SIGNATURE VERIFIED against a pinned key, is CLOCK-CHECKED, and then decides a
 * real BBS+ verification. Everything before this run stopped at "identity can read a bit out of a list
 * somebody hands it".
 *
 * NO NETWORK: the transport is `FakeStatusListHttp` throughout.
 */

import {
  UNSAFE_NO_CHECKS,
  checkPredicate,
  gateOnrampPredicate,
  generateIssuerKeyPair,
  issue,
  issuerIdFromPublicKey,
  prove,
  verifyDetailed,
} from '@stellaronramp/identity';
import type { Credential, KycClaims, ProofBinding } from '@stellaronramp/identity';
import { describe, expect, it } from 'vitest';

import { HardenedStatusListResolver } from '../../src/status/resolver.js';
import {
  DEFAULT_VALID_FROM,
  DOCUMENT_ISSUER,
  FakeStatusListHttp,
  ISSUER_PUBLIC_KEY,
  LIST_URL,
  OTHER_SEED,
  VERIFICATION_METHOD,
  publish,
} from './fixtures.js';

/** The two indices the round trip is about. */
const REVOKED_INDEX = 4242;
const LIVE_INDEX = 9001;

const BINDING: ProofBinding = {
  nonce: '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff',
  walletAddress: 'CBQHNAXSI55GX2GN6D67GK7BHVPSLJUGZQEU7WJ5LKR5PNUCGLIMAO4K',
  contractId: 'CAAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQC526',
  networkPassphrase: 'Test SDF Network ; September 2015',
  ledgerExpiry: 1_500_000,
};

const BBS_SEED = Uint8Array.from({ length: 32 }, (_, i) => i + 11);

interface Fixture {
  readonly publicKey: Uint8Array;
  readonly issuerId: string;
  readonly revoked: Credential;
  readonly live: Credential;
}

let cached: Fixture | undefined;

/** BBS+ issuance is ~10 ms each; cached so the whole file pays for it once. */
async function fixture(): Promise<Fixture> {
  if (cached === undefined) {
    const kp = await generateIssuerKeyPair(BBS_SEED);
    const issuerId = issuerIdFromPublicKey(kp.publicKey);
    const claims = (revocationIndex: number): KycClaims => ({
      schemaVersion: '1',
      issuerId,
      revocationIndex,
      issuedAt: 1_767_225_600,
      expiresAt: 1_900_000_000,
      subjectBinding: '3d1f2b6a9c8e4705b1d2c3a4f5e6978899aabbccddeeff001122334455667788',
      over18: true,
      over21: true,
      notSanctioned: true,
      notPep: true,
      jurisdictionOk: true,
      livenessOk: true,
    });
    cached = {
      publicKey: kp.publicKey,
      issuerId,
      revoked: await issue(claims(REVOKED_INDEX), kp.secretKey),
      live: await issue(claims(LIVE_INDEX), kp.secretKey),
    };
  }
  return cached;
}

/** A resolver pinned to our own publisher's key, served by a fake transport. */
function resolverFor(
  issuerId: string,
  http: FakeStatusListHttp,
  now = DEFAULT_VALID_FROM,
): HardenedStatusListResolver {
  return new HardenedStatusListResolver({
    issuers: [
      {
        issuerId,
        url: LIST_URL,
        publicKeyRaw: ISSUER_PUBLIC_KEY,
        documentIssuer: DOCUMENT_ISSUER,
        verificationMethod: VERIFICATION_METHOD,
      },
    ],
    http,
    now: () => now,
  });
}

describe('THE ROUND TRIP: publish -> dereference -> verifyDetailed', () => {
  it('a credential at the SET index verifies valid:FALSE with reason "revoked"', async () => {
    const f = await fixture();
    const document = await publish({ revoked: [REVOKED_INDEX] });
    const http = new FakeStatusListHttp({ document }, true);
    const resolver = resolverFor(f.issuerId, http);

    const proof = await prove(f.revoked, gateOnrampPredicate(), BINDING);
    const result = await checkPredicate(proof, gateOnrampPredicate(), f.publicKey, BINDING, {
      ...UNSAFE_NO_CHECKS,
      statusList: resolver.asStatusListResolver(),
    });

    expect(result.valid).toBe(false);
    expect(result.reason).toBe('revoked');
    expect(result.detail).toContain(String(REVOKED_INDEX));
    // And the bit really came off the wire, through the signature check.
    expect(http.callCount).toBe(1);
    expect(resolver.lastProvenance?.url).toBe(LIST_URL);
  });

  it('a credential at a CLEAR index verifies valid:TRUE against the same published list', async () => {
    const f = await fixture();
    const document = await publish({ revoked: [REVOKED_INDEX] });
    const resolver = resolverFor(f.issuerId, new FakeStatusListHttp({ document }, true));

    const proof = await prove(f.live, gateOnrampPredicate(), BINDING);
    const result = await checkPredicate(proof, gateOnrampPredicate(), f.publicKey, BINDING, {
      ...UNSAFE_NO_CHECKS,
      statusList: resolver.asStatusListResolver(),
    });

    expect(result.valid).toBe(true);
    expect(result.reason).toBeUndefined();
    expect(result.claims?.revocationIndex).toBe(LIVE_INDEX);
  });

  it('the SAME credential flips from valid to revoked when the issuer republishes', async () => {
    // The whole point of a revocation channel, demonstrated end to end.
    const f = await fixture();
    const proof = await prove(f.live, gateOnrampPredicate(), BINDING);

    const before = resolverFor(
      f.issuerId,
      new FakeStatusListHttp({ document: await publish({ revoked: [] }) }, true),
    );
    const after = resolverFor(
      f.issuerId,
      new FakeStatusListHttp({ document: await publish({ revoked: [LIVE_INDEX] }) }, true),
    );

    await expect(
      checkPredicate(proof, gateOnrampPredicate(), f.publicKey, BINDING, {
        ...UNSAFE_NO_CHECKS,
        statusList: before.asStatusListResolver(),
      }),
    ).resolves.toMatchObject({ valid: true });

    await expect(
      checkPredicate(proof, gateOnrampPredicate(), f.publicKey, BINDING, {
        ...UNSAFE_NO_CHECKS,
        statusList: after.asStatusListResolver(),
      }),
    ).resolves.toMatchObject({ valid: false, reason: 'revoked' });
  });

  it('works through verifyDetailed directly, not only through checkPredicate', async () => {
    const f = await fixture();
    const resolver = resolverFor(
      f.issuerId,
      new FakeStatusListHttp({ document: await publish({ revoked: [REVOKED_INDEX] }) }, true),
    );
    const proof = await prove(f.revoked, gateOnrampPredicate(), BINDING);
    const result = await verifyDetailed(proof, f.publicKey, BINDING, {
      ...UNSAFE_NO_CHECKS,
      statusList: resolver.asStatusListResolver(),
    });
    expect(result).toMatchObject({ valid: false, reason: 'revoked' });
  });

  it('resolves through a REDIRECT and still reaches the right verdict', async () => {
    const f = await fixture();
    const http = new FakeStatusListHttp([
      { status: 302, headers: { location: 'https://cdn.example/mirror' } },
      { document: await publish({ revoked: [REVOKED_INDEX] }) },
    ]);
    const proof = await prove(f.revoked, gateOnrampPredicate(), BINDING);
    const result = await checkPredicate(proof, gateOnrampPredicate(), f.publicKey, BINDING, {
      ...UNSAFE_NO_CHECKS,
      statusList: resolverFor(f.issuerId, http).asStatusListResolver(),
    });
    expect(result).toMatchObject({ valid: false, reason: 'revoked' });
    expect(http.urls).toHaveLength(2);
  });
});

/**
 * THE OTHER HALF OF THE DELIVERABLE, and the brief was explicit that asserting the resolver threw is
 * NOT enough: "assert that a resolver failure produces valid:false out of verifyDetailed, not merely
 * that your resolver threw."
 *
 * identity's status-list.ts says "Throwing from here fails verification closed (reason
 * status-list-invalid)". These tests prove that contract holds for OUR resolver's every failure mode.
 */
describe('EVERY resolver failure produces valid:FALSE out of verifyDetailed', () => {
  it.each([
    [
      'a plain-HTTP redirect (the MITM downgrade)',
      () => new FakeStatusListHttp([{ status: 302, headers: { location: 'http://evil/l' } }], true),
    ],
    [
      'an UNSIGNED list',
      async () => {
        const doc = await publish({ revoked: [] });
        const { proof: _p, ...unsigned } = doc;
        void _p;
        return new FakeStatusListHttp({ document: unsigned }, true);
      },
    ],
    [
      'a list signed by the WRONG key',
      async () =>
        new FakeStatusListHttp(
          { document: await publish({ revoked: [], signingKey: { seed: OTHER_SEED } }) },
          true,
        ),
    ],
    [
      'a list with the bitstring swapped to ALL-CLEAR after signing',
      async () => {
        const revokedDoc = await publish({ revoked: [REVOKED_INDEX] });
        const clear = await publish({ revoked: [] });
        return new FakeStatusListHttp(
          {
            document: {
              ...revokedDoc,
              credentialSubject: {
                ...revokedDoc.credentialSubject,
                encodedList: clear.credentialSubject.encodedList,
              },
            },
          },
          true,
        );
      },
    ],
    ['an HTTP 404', () => new FakeStatusListHttp({ status: 404, body: 'nope' }, true)],
    ['an HTTP 500', () => new FakeStatusListHttp({ status: 500, body: 'boom' }, true)],
    ['a body that is not JSON', () => new FakeStatusListHttp({ body: 'not json' }, true)],
    [
      'a transport failure',
      () => new FakeStatusListHttp({ throws: new Error('ECONNREFUSED') }, true),
    ],
    [
      'a timeout',
      () =>
        new FakeStatusListHttp(
          { throws: Object.assign(new Error('aborted'), { name: 'AbortError' }) },
          true,
        ),
    ],
    [
      'a SUSPENSION list answering a REVOCATION question',
      async () =>
        new FakeStatusListHttp(
          { document: await publish({ revoked: [], statusPurpose: 'suspension' }) },
          true,
        ),
    ],
    [
      'a redirect loop',
      () =>
        new FakeStatusListHttp([{ status: 302, headers: { location: 'https://a/loop' } }], true),
    ],
  ])('%s yields valid:false, not a silent un-revoke', async (_label, makeHttp) => {
    const f = await fixture();
    const http = await makeHttp();
    // The credential at the CLEAR index: if the resolver failed OPEN this would come back valid:true,
    // which is precisely the silent-un-revoke outcome being ruled out.
    const proof = await prove(f.live, gateOnrampPredicate(), BINDING);
    const result = await checkPredicate(proof, gateOnrampPredicate(), f.publicKey, BINDING, {
      ...UNSAFE_NO_CHECKS,
      statusList: resolverFor(f.issuerId, http).asStatusListResolver(),
    });
    expect(result.valid, 'a resolver failure must NEVER be valid:true').toBe(false);
    expect(result.reason).toBe('status-list-invalid');
  });

  it('an EXPIRED list yields valid:false rather than a stale bit', async () => {
    const f = await fixture();
    const document = await publish({
      revoked: [],
      validUntilSeconds: DEFAULT_VALID_FROM + 60,
    });
    const resolver = resolverFor(
      f.issuerId,
      new FakeStatusListHttp({ document }, true),
      DEFAULT_VALID_FROM + 120,
    );
    const proof = await prove(f.live, gateOnrampPredicate(), BINDING);
    const result = await checkPredicate(proof, gateOnrampPredicate(), f.publicKey, BINDING, {
      ...UNSAFE_NO_CHECKS,
      statusList: resolver.asStatusListResolver(),
    });
    expect(result).toMatchObject({ valid: false, reason: 'status-list-invalid' });
  });

  it('a STALE-but-unexpired list yields valid:false: the verifier bound really bites', async () => {
    const f = await fixture();
    const document = await publish({
      revoked: [],
      validUntilSeconds: DEFAULT_VALID_FROM + 86_400, // the issuer is happy for 24 h
    });
    const resolver = resolverFor(
      f.issuerId,
      new FakeStatusListHttp({ document }, true),
      DEFAULT_VALID_FROM + 3600, // 1 h old; our bound is 5 min
    );
    const proof = await prove(f.live, gateOnrampPredicate(), BINDING);
    const result = await checkPredicate(proof, gateOnrampPredicate(), f.publicKey, BINDING, {
      ...UNSAFE_NO_CHECKS,
      statusList: resolver.asStatusListResolver(),
    });
    expect(result).toMatchObject({ valid: false, reason: 'status-list-invalid' });
  });

  it('an UNPINNED issuer yields valid:false without a fetch', async () => {
    const f = await fixture();
    const http = new FakeStatusListHttp({ document: await publish({ revoked: [] }) }, true);
    // Pin a DIFFERENT issuerId than the credential's, so resolution cannot proceed.
    const resolver = resolverFor(`${'d'.repeat(64)}`, http);
    const proof = await prove(f.live, gateOnrampPredicate(), BINDING);
    const result = await checkPredicate(proof, gateOnrampPredicate(), f.publicKey, BINDING, {
      ...UNSAFE_NO_CHECKS,
      statusList: resolver.asStatusListResolver(),
    });
    expect(result).toMatchObject({ valid: false, reason: 'status-list-invalid' });
    expect(http.callCount).toBe(0);
  });
});

describe('the resolver receives the request identity promises it', () => {
  it('is called with {revocationIndex, issuerId, statusPurpose} from the DISCLOSED claims', async () => {
    const f = await fixture();
    const seen: unknown[] = [];
    const document = await publish({ revoked: [REVOKED_INDEX] });
    const inner = resolverFor(f.issuerId, new FakeStatusListHttp({ document }, true));
    const proof = await prove(f.revoked, gateOnrampPredicate(), BINDING);
    await checkPredicate(proof, gateOnrampPredicate(), f.publicKey, BINDING, {
      ...UNSAFE_NO_CHECKS,
      statusList: async (request) => {
        seen.push(request);
        return inner.resolve(request);
      },
    });
    expect(seen).toHaveLength(1);
    expect(seen[0]).toEqual({
      revocationIndex: REVOKED_INDEX,
      issuerId: f.issuerId,
      statusPurpose: 'revocation',
    });
  });
});
