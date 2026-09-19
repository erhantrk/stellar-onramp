/**
 * K4 BBS+ issuance: the six derived booleans plus the six metadata attributes, over the frozen
 * 12-attribute v1 schema, signed with `@stellaronramp/identity`'s `issue()`.
 *
 * NOTHING CRYPTOGRAPHIC IS REIMPLEMENTED HERE and that is the point rather than politeness about a
 * write lock: schema.ts's own header explains that adjacent boolean attributes differ only by
 * POSITION, so a second implementation of the index assignment is a way to mint a silently-wrong
 * credential whose BBS+ signature verifies perfectly.
 */

import {
  CLAIM_INDEX,
  SCHEMA_VERSION,
  SUBJECT_BINDING_SALT_BYTES,
  UNSAFE_NO_CHECKS,
  computeSubjectBinding,
  credentialAudit,
  gateOnrampPredicate,
  generateIssuerKeyPair,
  issuerIdFromPublicKey,
  prove,
  verifyDetailed,
} from '@stellaronramp/identity';
import type { IssuerKeyPair, ProofBinding } from '@stellaronramp/identity';
import { describe, expect, it } from 'vitest';

import {
  IssuanceError,
  freshSubjectBindingSalt,
  issueKycCredential,
} from '../../src/kyc/issue.js';
import type { IssueCredentialRequest } from '../../src/kyc/issue.js';
import { InMemoryRevocationIndexAllocator } from '../../src/kyc/revocation-index.js';
import { claimBitmap } from '../../src/kyc/claims.js';
import { PERSISTED_COLUMNS } from '../../src/kyc/record.js';
import type { ClaimSet } from '../../src/kyc/provider.js';

const WALLET = 'CBQHNAXSI55GX2GN6D67GK7BHVPSLJUGZQEU7WJ5LKR5PNUCGLIMAO4K';
const OTHER_WALLET = 'CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC';
const ISSUED_AT = 1_800_000_000;
const EXPIRES_AT = ISSUED_AT + 365 * 24 * 60 * 60;

const ALL_TRUE: ClaimSet = {
  over18: true,
  over21: true,
  notSanctioned: true,
  notPep: true,
  jurisdictionOk: true,
  livenessOk: true,
};

let keys: IssuerKeyPair | undefined;
async function issuer(): Promise<IssuerKeyPair> {
  keys ??= await generateIssuerKeyPair(Uint8Array.from({ length: 32 }, (_, i) => i + 11));
  return keys;
}

async function request(
  over: Partial<IssueCredentialRequest> = {},
): Promise<IssueCredentialRequest> {
  const kp = await issuer();
  return {
    claims: ALL_TRUE,
    walletAddress: WALLET,
    issuedAt: ISSUED_AT,
    expiresAt: EXPIRES_AT,
    issuerSecretKey: kp.secretKey,
    issuerPublicKey: kp.publicKey,
    allocator: new InMemoryRevocationIndexAllocator({ start: 4242 }),
    provider: 'kyc-provider',
    providerRefId: '5f2f7c1e9a1b2c3d4e5f6071',
    subjectId: 'sub_opaque_01HX9Q2M4K',
    ...over,
  };
}

describe('the 12 attributes are identity\'s, at identity\'s indices', () => {
  it('signs all twelve and nothing else', async () => {
    const issued = await issueKycCredential(await request());
    expect(Object.keys(issued.credential.claims)).toHaveLength(12);
    expect(Object.keys(issued.credential.claims).sort()).toEqual(Object.keys(CLAIM_INDEX).sort());
  });

  it('places every value at the index CLAIM_INDEX says, so a mixed-up verifier cannot happen', async () => {
    const kp = await issuer();
    const issued = await issueKycCredential(await request());
    const c = issued.credential.claims;
    expect(CLAIM_INDEX.schemaVersion).toBe(0);
    expect(c.schemaVersion).toBe(SCHEMA_VERSION);
    expect(CLAIM_INDEX.issuerId).toBe(1);
    expect(c.issuerId).toBe(issuerIdFromPublicKey(kp.publicKey));
    expect(CLAIM_INDEX.revocationIndex).toBe(2);
    expect(c.revocationIndex).toBe(4242);
    expect(CLAIM_INDEX.issuedAt).toBe(3);
    expect(c.issuedAt).toBe(ISSUED_AT);
    expect(CLAIM_INDEX.expiresAt).toBe(4);
    expect(c.expiresAt).toBe(EXPIRES_AT);
    expect(CLAIM_INDEX.subjectBinding).toBe(5);
    expect(c.subjectBinding).toMatch(/^[0-9a-f]{64}$/);
    expect(CLAIM_INDEX.over18).toBe(6);
    expect(CLAIM_INDEX.livenessOk).toBe(11);
  });

  /**
   * The six booleans must land in the right SLOTS. Six single-true ClaimSets, each of which must set
   * exactly one boolean attribute — a transposition of any adjacent pair fails here.
   */
  it.each([
    'over18',
    'over21',
    'notSanctioned',
    'notPep',
    'jurisdictionOk',
    'livenessOk',
  ] as const)('a ClaimSet with only %s true sets exactly that attribute', async (name) => {
    const claims: ClaimSet = { ...ALL_TRUE };
    for (const k of Object.keys(claims) as Array<keyof ClaimSet>) {
      (claims as unknown as Record<string, boolean>)[k] = k === name;
    }
    // A single-true set can produce bitmap 0 (notPep / livenessOk have no chain bit), which is
    // refused; give those a chain-bearing companion so issuance can proceed.
    const usable: ClaimSet =
      claimBitmap(claims) === 0 ? { ...claims, over18: true } : claims;
    const issued = await issueKycCredential(await request({ claims: usable }));
    for (const k of Object.keys(usable) as Array<keyof ClaimSet>) {
      expect(issued.credential.claims[k], `${k} must round-trip`).toBe(usable[k]);
    }
  });

  it('THERE IS NO name, DOB, country or document number attribute to leak into', async () => {
    const issued = await issueKycCredential(await request());
    const keys = Object.keys(issued.credential.claims);
    for (const forbidden of [
      'name',
      'fullName',
      'dob',
      'dateOfBirth',
      'country',
      'residenceCountry',
      'documentNumber',
      'age',
    ]) {
      expect(keys).not.toContain(forbidden);
    }
  });

  it('the issued credential VERIFIES, and a gate proof over it verifies too', async () => {
    const kp = await issuer();
    const issued = await issueKycCredential(await request());
    const binding: ProofBinding = {
      nonce: '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff',
      walletAddress: WALLET,
      contractId: 'CAAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQC526',
      networkPassphrase: 'Test SDF Network ; September 2015',
      ledgerExpiry: 1_500_000,
    };
    const proof = await prove(issued.credential, gateOnrampPredicate(), binding);
    const result = await verifyDetailed(proof, kp.publicKey, binding, {
      ...UNSAFE_NO_CHECKS,
      // The subject binding really is over THIS wallet and THIS salt.
      expectedSubjectBinding: computeSubjectBinding(WALLET, issued.subjectBindingSalt),
      currentTime: ISSUED_AT + 60,
    });
    expect(result.valid).toBe(true);
  });

  it('a credentialAudit proof discloses the metadata block including revocationIndex', async () => {
    const kp = await issuer();
    const issued = await issueKycCredential(await request());
    const binding: ProofBinding = {
      nonce: 'ff'.repeat(32),
      walletAddress: WALLET,
      contractId: 'CAAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQC526',
      networkPassphrase: 'Test SDF Network ; September 2015',
      ledgerExpiry: 1_500_000,
    };
    const proof = await prove(issued.credential, credentialAudit(), binding);
    const result = await verifyDetailed(proof, kp.publicKey, binding, UNSAFE_NO_CHECKS);
    expect(result.valid).toBe(true);
    expect(result.claims?.revocationIndex).toBe(4242);
  });
});

describe('the SUBJECT-BINDING SALT: fresh, CSPRNG, per credential', () => {
  it('is exactly identity\'s required width', () => {
    expect(freshSubjectBindingSalt()).toHaveLength(SUBJECT_BINDING_SALT_BYTES);
    expect(SUBJECT_BINDING_SALT_BYTES).toBe(32);
  });

  /**
   * THE INVARIANT IS UNIQUENESS PER CREDENTIAL, not confidentiality — the salt is disclosed to every
   * verifier. A REUSED salt turns `subjectBinding` from a commitment into a LOOKUP KEY, and a CONSTANT
   * salt makes it a pure function of a public address, i.e. an ordinary rainbow-table target over a set
   * enumerable from the ledger.
   */
  it('is DIFFERENT for every credential, across 200 draws', () => {
    const seen = new Set<string>();
    for (let i = 0; i < 200; i += 1) {
      seen.add(Buffer.from(freshSubjectBindingSalt()).toString('hex'));
    }
    expect(seen.size).toBe(200);
  });

  it('has full-byte entropy at every one of the 32 positions', () => {
    // A "salt" that is constant in any position is that many bits short.
    const values: Array<Set<number>> = Array.from({ length: 32 }, () => new Set<number>());
    for (let i = 0; i < 400; i += 1) {
      const salt = freshSubjectBindingSalt();
      for (let j = 0; j < 32; j += 1) values[j]!.add(salt[j]!);
    }
    for (let j = 0; j < 32; j += 1) {
      expect(values[j]!.size, `position ${j} is not varying`).toBeGreaterThan(100);
    }
  });

  it('two credentials for the SAME wallet get DIFFERENT bindings, which is the anti-correlation point', async () => {
    const a = await issueKycCredential(await request());
    const b = await issueKycCredential(await request());
    expect(a.credential.claims.subjectBinding).not.toBe(b.credential.claims.subjectBinding);
    expect(Buffer.from(a.subjectBindingSalt).toString('hex')).not.toBe(
      Buffer.from(b.subjectBindingSalt).toString('hex'),
    );
  });

  it('a SHARED salt makes the binding a LOOKUP KEY over public addresses — demonstrated', async () => {
    // With a shared salt, anyone holding it can test any candidate address. Stellar addresses are
    // public, so this is the cross-linkability the salt exists to prevent.
    const shared = freshSubjectBindingSalt();
    const a = await issueKycCredential(await request({ subjectBindingSalt: shared }));
    const b = await issueKycCredential(
      await request({ walletAddress: OTHER_WALLET, subjectBindingSalt: shared }),
    );
    // The bindings differ (so nothing breaks cryptographically) ...
    expect(a.credential.claims.subjectBinding).not.toBe(b.credential.claims.subjectBinding);
    // ... but holding the salt lets an observer CONFIRM which address each belongs to.
    expect(computeSubjectBinding(WALLET, shared)).toBe(a.credential.claims.subjectBinding);
    expect(computeSubjectBinding(OTHER_WALLET, shared)).toBe(b.credential.claims.subjectBinding);
  });

  it('is NOT persisted: it is not one of the design\'s eleven columns', async () => {
    const issued = await issueKycCredential(await request());
    const saltHex = Buffer.from(issued.subjectBindingSalt).toString('hex');
    expect(JSON.stringify(issued.record)).not.toContain(saltHex);
    expect(PERSISTED_COLUMNS).not.toContain('subject_binding_salt');
    // It IS returned, because the holder needs it or the credential is unusable.
    expect(issued.subjectBindingSalt).toHaveLength(32);
  });

  it('refuses a salt of the wrong width', async () => {
    for (const subjectBindingSalt of [new Uint8Array(31), new Uint8Array(33), new Uint8Array(0)]) {
      await expect(issueKycCredential(await request({ subjectBindingSalt }))).rejects.toThrow(
        IssuanceError,
      );
    }
  });

  it('refuses a non-Stellar wallet address BEFORE anything is allocated', async () => {
    const allocator = new InMemoryRevocationIndexAllocator();
    for (const walletAddress of ['', 'not-an-address', 'X'.repeat(56), WALLET.toLowerCase()]) {
      await expect(issueKycCredential(await request({ walletAddress, allocator }))).rejects.toThrow();
    }
    expect(allocator.next, 'a rejected request must not burn an index').toBe(0);
  });
});

describe('the persisted tuple comes out of issuance already built and validated', () => {
  it('carries exactly the eleven columns, with the values issuance actually used', async () => {
    const kp = await issuer();
    const issued = await issueKycCredential(await request());
    expect(issued.record).toEqual({
      provider: 'kyc-provider',
      providerRefId: '5f2f7c1e9a1b2c3d4e5f6071',
      subjectId: 'sub_opaque_01HX9Q2M4K',
      walletCAddr: WALLET,
      claimBitmap: claimBitmap(ALL_TRUE),
      schemaVersion: SCHEMA_VERSION,
      issuedAt: ISSUED_AT,
      expiresAt: EXPIRES_AT,
      revocationIndex: 4242,
      issuerId: issuerIdFromPublicKey(kp.publicKey),
    });
  });

  it('the record\'s revocationIndex is the SAME value signed into the credential', async () => {
    // This is the audit link from the on-chain attestation back to the status-list bit. If these two
    // ever disagreed, revoking the status-list bit would not correspond to the attested credential.
    const issued = await issueKycCredential(await request());
    expect(issued.record.revocationIndex).toBe(issued.credential.claims.revocationIndex);
  });


  it('the claimBitmap it reports is the one the chain signer will attest', async () => {
    const issued = await issueKycCredential(await request());
    expect(issued.claimBitmap).toBe(issued.record.claimBitmap);
    expect(issued.claimBitmap).toBe(claimBitmap(ALL_TRUE));
  });

  it('serialises to something with no PII by construction', async () => {
    const issued = await issueKycCredential(await request());
    expect(issued.serialized).toBeDefined();
    expect(JSON.stringify(issued.serialized)).not.toContain('dob');
  });
});

describe('issuance refuses what it cannot honestly produce', () => {
  /**
   * The contract refuses `claims == 0` with #12 EmptyClaims, so this credential could never be
   * attested. Refusing here NAMES the reason before a ~10 ms BBS+ signature is spent.
   */
  it('refuses a credential whose on-chain bitmap would be 0', async () => {
    const onlyOffChain: ClaimSet = {
      over18: false,
      over21: false,
      notSanctioned: false,
      notPep: true,
      jurisdictionOk: false,
      livenessOk: true,
    };
    const err = await issueKycCredential(await request({ claims: onlyOffChain })).catch(
      (e: Error) => e,
    );
    expect(err).toBeInstanceOf(IssuanceError);
    expect((err as Error).message).toContain('#12 EmptyClaims');
    // And it names WHY notPep+livenessOk alone is bitmap 0, which is the surprising part.
    expect((err as Error).message).toContain('notPep and');
  });

  it('does NOT burn a revocation index on a request it refuses cheaply', async () => {
    const allocator = new InMemoryRevocationIndexAllocator();
    const allFalse: ClaimSet = {
      over18: false,
      over21: false,
      notSanctioned: false,
      notPep: false,
      jurisdictionOk: false,
      livenessOk: false,
    };
    await expect(issueKycCredential(await request({ claims: allFalse, allocator }))).rejects.toThrow();
    expect(allocator.next).toBe(0);
  });

  it.each([
    ['a non-integer issuedAt', { issuedAt: 1.5 }],
    ['a negative issuedAt', { issuedAt: -1 }],
    ['expiresAt equal to issuedAt', { expiresAt: ISSUED_AT }],
    ['expiresAt before issuedAt', { expiresAt: ISSUED_AT - 1 }],
    ['a non-integer expiresAt', { expiresAt: ISSUED_AT + 0.5 }],
  ])('refuses %s', async (_label, over) => {
    await expect(issueKycCredential(await request(over))).rejects.toThrow(IssuanceError);
  });

  it.each([31, 33, 0])('refuses a %s-byte issuer secret key', async (length) => {
    await expect(
      issueKycCredential(await request({ issuerSecretKey: new Uint8Array(length) })),
    ).rejects.toThrow(/32 bytes/);
  });

  it('allocates the index LAST among validations, so a malformed request burns nothing', async () => {
    // ORDER MATTERS: allocation is the only irreversible step.
    const allocator = new InMemoryRevocationIndexAllocator();
    for (const over of [
      { issuedAt: -1 },
      { expiresAt: ISSUED_AT },
      { issuerSecretKey: new Uint8Array(31) },
      { walletAddress: 'nope' },
    ]) {
      await expect(
        issueKycCredential(await request({ ...over, allocator })),
      ).rejects.toThrow();
    }
    expect(allocator.next).toBe(0);
  });

  it('two issuances get DIFFERENT revocation indexes from one allocator', async () => {
    const allocator = new InMemoryRevocationIndexAllocator({ start: 100 });
    const a = await issueKycCredential(await request({ allocator }));
    const b = await issueKycCredential(await request({ allocator }));
    expect(a.record.revocationIndex).toBe(100);
    expect(b.record.revocationIndex).toBe(101);
    expect(a.record.revocationIndex).not.toBe(b.record.revocationIndex);
  });

  it('propagates an allocator failure rather than issuing with a guessed index', async () => {
    const exhausted = new InMemoryRevocationIndexAllocator({ start: 5, max: 5 });
    await issueKycCredential(await request({ allocator: exhausted }));
    await expect(issueKycCredential(await request({ allocator: exhausted }))).rejects.toThrow(
      /exhausted/,
    );
  });
});
