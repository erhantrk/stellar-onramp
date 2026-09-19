/**
 * Cross-schema-version and issuer-identity confusion.
 *
 * `Proof.schemaVersion` is an UNSIGNED label the presenter chooses, so the `schema-version` check
 * at the top of `verifyDetailed` proves nothing on its own — a hostile presenter just writes "1".
 * Two things actually stand between a v1 verifier and a foreign credential:
 *
 *   1. `CREDENTIAL_HEADER`, which embeds the version and is hashed into the BBS+ `domain`. A
 *      credential signed under the v2 header cannot satisfy a v1 ProofVerify. This is the load-
 *      bearing defence and it is exercised below.
 *   2. The SIGNED index-0 message — but only when the presentation discloses it. Predicates that
 *      disclosed in the standard on-ramp proof.
 *
 * These credentials are hand-signed with `bbs.sign` because `issue()` refuses to build them —
 * which is correct, and also why the checks below cannot be reached through the honest API.
 */

import * as bbs from '@digitalbazaar/bbs-signatures';
import { utf8ToBytes } from '@noble/hashes/utils.js';
import { describe, expect, it } from 'vitest';

import {
  UNSAFE_NO_CHECKS,
  CIPHERSUITE,
  CLAIM_INDEX,
  SCHEMA_ATTRIBUTE_COUNT,
  SCHEMA_VERSION,
  generateIssuerKeyPair,
  issuerIdFromPublicKey,
  presentationHeaderFor,
  verifyDetailed,
  type Proof,
} from '../src/index.js';
import { BASE_BINDING, ISSUER_SEED } from './helpers.js';


const V1_HEADER = 'stellaronramp/kyc-credential/v1';
const V2_HEADER = 'stellaronramp/kyc-credential/v2';

/** A 12-message set whose signed index 0 claims schema v2, and whose issuerId names nobody. */
function foreignMessages(issuerId: string): string[] {
  return [
    'schemaVersion=2',
    `issuerId=${issuerId}`,
    'revocationIndex=7',
    'issuedAt=1767225600',
    'expiresAt=1782950400',
    `subjectBinding=${'bb'.repeat(32)}`,
    'over18=true',
    'over21=true',
    'notSanctioned=true',
    'notPep=true',
    'jurisdictionOk=true',
    'livenessOk=true',
  ];
}

async function handSignedPresentation(opts: {
  header: string;
  disclose: readonly number[];
  issuerId?: string;
}): Promise<{ proof: Proof; publicKey: Uint8Array }> {
  const kp = await generateIssuerKeyPair(ISSUER_SEED);
  const text = foreignMessages(opts.issuerId ?? issuerIdFromPublicKey(kp.publicKey));
  const messages = text.map((m) => utf8ToBytes(m));
  const signature = await bbs.sign({
    secretKey: kp.secretKey,
    publicKey: kp.publicKey,
    header: utf8ToBytes(opts.header),
    messages,
    ciphersuite: CIPHERSUITE,
  });
  const disclosedIndexes = [...opts.disclose];
  const raw = await bbs.deriveProof({
    publicKey: kp.publicKey,
    signature,
    header: utf8ToBytes(opts.header),
    messages,
    presentationHeader: presentationHeaderFor(BASE_BINDING),
    disclosedMessageIndexes: disclosedIndexes,
    ciphersuite: CIPHERSUITE,
  });
  return {
    publicKey: kp.publicKey,
    proof: {
      // The presenter lies about the version label, because nothing signs it.
      schemaVersion: SCHEMA_VERSION,
      proof: raw,
      disclosedIndexes,
      disclosedMessages: disclosedIndexes.map((i) => text[i] as string),
      totalMessages: SCHEMA_ATTRIBUTE_COUNT,
      binding: BASE_BINDING,
    },
  };
}

describe('cross-schema-version confusion', () => {
  it('rejects a credential signed under the v2 BBS+ header, whatever it claims to be', async () => {
    const { proof, publicKey } = await handSignedPresentation({
      header: V2_HEADER,
      disclose: [CLAIM_INDEX.over18, CLAIM_INDEX.notSanctioned],
    });
    const r = await verifyDetailed(proof, publicKey, BASE_BINDING, UNSAFE_NO_CHECKS);
    expect(r.valid).toBe(false);
    // The version is inside `domain`, so this is a cryptographic rejection, not a label check.
    expect(r.reason).toBe('bbs-invalid');
  });

  it('rejects a signed schemaVersion=2 message when the presentation discloses index 0', async () => {
    const { proof, publicKey } = await handSignedPresentation({
      header: V1_HEADER,
      disclose: [CLAIM_INDEX.schemaVersion, CLAIM_INDEX.over18],
    });
    const r = await verifyDetailed(proof, publicKey, BASE_BINDING, UNSAFE_NO_CHECKS);
    expect(r.valid).toBe(false);
    expect(r.reason).toBe('schema-version');
    expect(r.detail).toMatch(/signed as schema v2/);
  });

  it('the unsigned Proof.schemaVersion label alone stops nothing — index 0 must be disclosed', async () => {
    // Same credential, same lie, but index 0 stays hidden: nothing in the presentation contradicts
    // the "1" the presenter wrote. This is the concrete reason a gate predicate should disclose
    const { proof, publicKey } = await handSignedPresentation({
      header: V1_HEADER,
      disclose: [CLAIM_INDEX.over18, CLAIM_INDEX.notSanctioned],
    });
    const r = await verifyDetailed(proof, publicKey, BASE_BINDING, UNSAFE_NO_CHECKS);
    expect(r.valid).toBe(true);
    expect(proof.disclosedIndexes).not.toContain(CLAIM_INDEX.schemaVersion);
  });
});

describe('disclosed issuerId vs the verifying key', () => {
  it('rejects a credential whose signed issuerId names a different key', async () => {
    const { proof, publicKey } = await handSignedPresentation({
      header: V1_HEADER,
      issuerId: 'aa'.repeat(32),
      disclose: [CLAIM_INDEX.issuerId, CLAIM_INDEX.over18],
    });
    const r = await verifyDetailed(proof, publicKey, BASE_BINDING, UNSAFE_NO_CHECKS);
    expect(r.valid).toBe(false);
    expect(r.reason).toBe('claim-mismatch');
    expect(r.detail).toMatch(/issuerId/);
  });

  it('accepts the honest case where issuerId is sha256 of the verifying key', async () => {
    const { proof, publicKey } = await handSignedPresentation({
      header: V1_HEADER,
      disclose: [CLAIM_INDEX.issuerId, CLAIM_INDEX.over18],
    });
    const r = await verifyDetailed(proof, publicKey, BASE_BINDING, UNSAFE_NO_CHECKS);
    expect(r.valid).toBe(true);
    expect(r.claims?.issuerId).toBe(issuerIdFromPublicKey(publicKey));
  });
});
