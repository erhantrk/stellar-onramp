/**
 * Shared fixtures. A REAL issued credential and REAL derived proof — splitProof decompresses G1
 * points with curve validation, so byte-faked proofs cannot drive the wire builders. Memoized per
 * process because BLS12-381 derivation costs real milliseconds and several suites want it.
 */

import type { Credential, IssuerKeyPair, Proof } from '@stellaronramp/identity';
import {
  computeSubjectBinding,
  gateOnrampPredicate,
  generateIssuerKeyPair,
  issue,
  issuerIdFromPublicKey,
  prove,
} from '@stellaronramp/identity';

/** Deterministic test issuer (NOT the repo fixture — that one is registered on live testnet). */
export const TEST_ISSUER_SEED = new Uint8Array(32).fill(11);

/** A syntactically valid (never funded) wallet C-address shape for offline tests. */
export const TEST_WALLET_C = 'CAJJ64SHO3R6L6ISWOD2NXACZXMQA6SAUXADCTSHDNLVZQ6Q3O5IVOVW';
export const TEST_GATE = 'CABAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAFNSZ';
export const TEST_NETWORK_PASSPHRASE = 'Test SDF Network ; September 2015';

export interface Fixture {
  readonly issuer: IssuerKeyPair;
  readonly issuerIdHex: string;
  readonly credential: Credential;
  /** A gate-predicate proof bound to TEST_WALLET_C with a deterministic nonce. */
  readonly proof: Proof;
  readonly nonceHex: string;
}

let fixturePromise: Promise<Fixture> | undefined;

export function fixture(): Promise<Fixture> {
  fixturePromise ??= (async () => {
    const issuer = await generateIssuerKeyPair(TEST_ISSUER_SEED);
    const issuerIdHex = issuerIdFromPublicKey(issuer.publicKey);
    const salt = new Uint8Array(32).fill(3);
    const nowSec = 1_755_000_000;
    const credential = await issue(
      {
        schemaVersion: '1',
        issuerId: issuerIdHex,
        revocationIndex: 4242,
        issuedAt: nowSec,
        expiresAt: nowSec + 90 * 24 * 3600,
        subjectBinding: computeSubjectBinding(TEST_WALLET_C, salt),
        over18: true,
        over21: true,
        notSanctioned: true,
        notPep: true,
        jurisdictionOk: true,
        livenessOk: true,
      },
      issuer.secretKey,
    );
    // A fixed nonce keeps every derived assertion reproducible run-to-run.
    const nonceHex = 'c'.repeat(64);
    const proof = await prove(credential, gateOnrampPredicate(), {
      nonce: nonceHex,
      walletAddress: TEST_WALLET_C,
      contractId: TEST_GATE,
      networkPassphrase: TEST_NETWORK_PASSPHRASE,
      ledgerExpiry: 4_196_173,
    });
    return { issuer, issuerIdHex, credential, proof, nonceHex };
  })();
  return fixturePromise;
}
