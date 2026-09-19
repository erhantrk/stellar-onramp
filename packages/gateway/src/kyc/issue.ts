/**
 * BBS+ issuance: the six derived booleans plus the six metadata attributes, signed with the issuer
 * key, over the frozen 12-attribute v1 schema.
 *
 * Every cryptographic operation here is `@stellaronramp/identity`'s. Nothing is reimplemented and
 * nothing in that package is written to — the indices, the canonical `name=value` encoding, the
 * ciphersuite, the constant header and the subject-binding hash are all imported. That is not
 * politeness about a write lock: schema.ts's own header explains that adjacent boolean attributes
 * differ only by POSITION, so a second implementation of the index assignment is a way to mint a
 * silently-wrong credential whose signature verifies perfectly.
 *
 *   0 schemaVersion  1 issuerId       2 revocationIndex  3 issuedAt
 *   4 expiresAt      5 subjectBinding 6 over18           7 over21
 *   8 notSanctioned  9 notPep        10 jurisdictionOk  11 livenessOk
 *
 * `not_sanctioned`) while the implemented `CLAIM_INDEX` is camelCase. THE CODE WINS, and the names
 * are imported rather than retyped so the question cannot arise at a call site.
 *
 * THERE IS NO NAME, NO DOB, NO COUNTRY AND NO DOCUMENT NUMBER IN THE SCHEMA. The credential cannot
 * leak PII because it does not contain any. test/kyc/pii.test.ts asserts that mechanically, over the
 * serialised credential, in all four encodings including sha256.
 */

import { randomBytes } from 'node:crypto';

import {
  SCHEMA_VERSION,
  SUBJECT_BINDING_SALT_BYTES,
  computeSubjectBinding,
  issue,
  issuerIdFromPublicKey,
  serializeCredential,
} from '@stellaronramp/identity';
import type { Credential, KycClaims, SerializedCredential } from '@stellaronramp/identity';

import { claimBitmap } from './claims.js';
import type { ClaimSet } from './provider.js';
import { assertUsableRevocationIndex } from './revocation-index.js';
import type { RevocationIndexAllocator } from './revocation-index.js';
import { buildIssuanceRecord } from './record.js';
import type { IssuanceRecord } from './record.js';

export class IssuanceError extends Error {
  override readonly name = 'IssuanceError';
}

/**
 * THE SUBJECT-BINDING SALT, AND WHERE IT COMES FROM. This is the security-relevant part of issuance
 * and it deserves the space.
 *
 * schema.ts documents what it is FOR: without it a BBS+ proof says only "SOME credential from this
 * issuer says over18=true" and one KYC'd holder can gate an unlimited number of wallets.
 *
 * WHERE THE SALT COMES FROM: a fresh 32 bytes from `node:crypto.randomBytes` — a CSPRNG — PER
 * CREDENTIAL. It is returned to the caller alongside the credential and is the HOLDER's to keep; the
 * relying party receives it out of band with the presentation, because it needs the salt to recompute
 * `computeSubjectBinding(walletAddress, salt)` and compare — that is `VerifyOptions
 * .expectedSubjectBinding`.
 *
 * WHAT HAPPENS IF IT IS REUSED ACROSS SUBJECTS, which is the question worth answering precisely:
 *
 *   * Reused across TWO WALLETS of the SAME person: the two bindings are `sha256(wallet1‖s)` and
 *     `sha256(wallet2‖s)`, which are different values, so nothing breaks cryptographically. But
 *     anyone holding the salt (i.e. any relying party either wallet presented to) can now test any
 *     candidate address against it, and Stellar addresses are public. So a shared salt turns
 *     `subjectBinding` from a commitment into a LOOKUP KEY: a relying party can enumerate the
 *     addresses it knows and discover which other wallets share the credential. That is precisely the
 *     cross-linkability the salt exists to prevent (schema.ts: "so that the same wallet address does
 *     not produce the same commitment across issuers").
 *   * Reused across TWO PEOPLE: same as above plus the two credentials become linkable to each other
 *     the moment both salts are seen to be equal.
 *   * A CONSTANT salt, e.g. all zeros or a per-deployment secret: `subjectBinding` becomes a pure
 *     function of the wallet address, so it is an ordinary rainbow-table target over the set of all
 *     Stellar addresses — which is enumerable from the ledger. `subjectBinding` would then be
 *     equivalent to publishing the address, and the credential's whole "no address in the clear"
 *     property is gone.
 *
 * It is NOT a secret in the cryptographic sense (schema.ts says so, and it is right: it is disclosed
 * to every verifier). It is an ANTI-CORRELATION nonce. The invariant is UNIQUENESS PER CREDENTIAL,
 * not confidentiality, which is why it is generated here from a CSPRNG rather than derived from
 * anything — a derived salt is a salt whose uniqueness depends on the uniqueness of its inputs, and
 * `sha256(walletAddress)` as a salt would be a constant per wallet, i.e. case three above.
 */
export function freshSubjectBindingSalt(): Uint8Array {
  return new Uint8Array(randomBytes(SUBJECT_BINDING_SALT_BYTES));
}

export interface IssueCredentialRequest {
  /** The six booleans from `deriveClaims`. */
  readonly claims: ClaimSet;
  /** Wallet C- or G-address the credential is bound to. */
  readonly walletAddress: string;
  /** Unix seconds. */
  readonly issuedAt: number;
  /** Unix seconds. Must be strictly after `issuedAt`. */
  readonly expiresAt: number;
  /** BBS+ issuer secret key, 32 bytes. */
  readonly issuerSecretKey: Uint8Array;
  /** 96-byte compressed G2. Supplied so `issuerId` need not be recomputed from the secret. */
  readonly issuerPublicKey: Uint8Array;
  /** Where the unique status-list index comes from. */
  readonly allocator: RevocationIndexAllocator;
  /** Provider adapter id, for the persisted tuple. */
  readonly provider: string;
  readonly providerRefId: string;
  /** Our own opaque subject id. Must not be derived from PII. */
  readonly subjectId: string;
  /**
   * Override the salt. FOR TESTS AND FOR A DETERMINISTIC RE-ISSUE ONLY. If you pass this in
   * production you own the uniqueness argument above.
   */
  readonly subjectBindingSalt?: Uint8Array;
}

export interface IssuedCredential {
  readonly credential: Credential;
  /** Ready to hand to a holder's storage. Contains no PII by construction. */
  readonly serialized: SerializedCredential;
  /**
   * and the tuple is exhaustive. It must reach the holder, or the credential is unusable.
   */
  readonly subjectBindingSalt: Uint8Array;
  readonly record: IssuanceRecord;
  /** The u32 the chain signer will attest. */
  readonly claimBitmap: number;
}

/**
 * Issue one credential.
 *
 * ORDER MATTERS AND IS DELIBERATE. The revocation index is allocated LAST among the validations and
 * FIRST among the side effects, because allocation is the only irreversible step: if `issue()` throws
 * after allocation the index is burned (never reused — see revocation-index.ts) and that is the
 * correct, cheap outcome. If the index were allocated before the cheap validations, every malformed
 * request would burn one.
 */
export async function issueKycCredential(
  request: IssueCredentialRequest,
): Promise<IssuedCredential> {
  if (!Number.isInteger(request.issuedAt) || request.issuedAt < 0) {
    throw new IssuanceError(`refusing to issue with a non-integer issuedAt: ${String(request.issuedAt)}`);
  }
  if (!Number.isInteger(request.expiresAt) || request.expiresAt <= request.issuedAt) {
    throw new IssuanceError(
      `refusing to issue a credential whose expiresAt (${String(request.expiresAt)}) is not ` +
        `strictly after its issuedAt (${request.issuedAt}); identity's issue() enforces the same ` +
        'thing and this check exists to name it before a key is touched',
    );
  }
  if (!(request.issuerSecretKey instanceof Uint8Array) || request.issuerSecretKey.length !== 32) {
    throw new IssuanceError('refusing to issue: issuerSecretKey must be 32 bytes');
  }
  const bitmap = claimBitmap(request.claims);
  if (bitmap === 0) {
    // The contract refuses `claims == 0` with #12 EmptyClaims, so this credential could never be
    // attested. Refusing here names the reason before a BBS+ signature (~10 ms) is spent.
    throw new IssuanceError(
      'refusing to issue a credential whose on-chain claim bitmap would be 0; kyc-gate rejects that ' +
        'with #12 EmptyClaims, so the credential could never be attested. Note that notPep and ' +
        'livenessOk have NO on-chain bit, so a credential asserting only those two is bitmap 0.',
    );
  }

  const salt = request.subjectBindingSalt ?? freshSubjectBindingSalt();
  if (salt.length !== SUBJECT_BINDING_SALT_BYTES) {
    throw new IssuanceError(
      `refusing to issue with a ${salt.length}-byte subject-binding salt; identity requires exactly ` +
        `${SUBJECT_BINDING_SALT_BYTES}`,
    );
  }
  // Throws on a non-Stellar address, before anything is allocated.
  const subjectBinding = computeSubjectBinding(request.walletAddress, salt);
  const issuerId = issuerIdFromPublicKey(request.issuerPublicKey);

  const revocationIndex = assertUsableRevocationIndex(await request.allocator.allocate());

  const claims: KycClaims = {
    schemaVersion: SCHEMA_VERSION,
    issuerId,
    revocationIndex,
    issuedAt: request.issuedAt,
    expiresAt: request.expiresAt,
    subjectBinding,
    over18: request.claims.over18,
    over21: request.claims.over21,
    notSanctioned: request.claims.notSanctioned,
    notPep: request.claims.notPep,
    jurisdictionOk: request.claims.jurisdictionOk,
    livenessOk: request.claims.livenessOk,
  };

  const credential = await issue(claims, request.issuerSecretKey);

  const record = buildIssuanceRecord({
    provider: request.provider,
    providerRefId: request.providerRefId,
    subjectId: request.subjectId,
    walletCAddr: request.walletAddress,
    claimBitmap: bitmap,
    schemaVersion: SCHEMA_VERSION,
    issuedAt: request.issuedAt,
    expiresAt: request.expiresAt,
    revocationIndex,
    issuerId,
  });

  return {
    credential,
    serialized: serializeCredential(credential),
    subjectBindingSalt: salt,
    record,
    claimBitmap: bitmap,
  };
}
