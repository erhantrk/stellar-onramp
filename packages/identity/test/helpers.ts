import {
  SCHEMA_VERSION,
  generateIssuerKeyPair,
  issue,
  issuerIdFromPublicKey,
  type Credential,
  type IssuerKeyPair,
  type KycClaims,
  type ProofBinding,
} from '../src/index.js';

/** Same seed as the fixtures, so tests and vectors talk about the same issuer. */
export const ISSUER_SEED = Uint8Array.from({ length: 32 }, (_, i) => i + 1);
export const OTHER_SEED = Uint8Array.from({ length: 32 }, (_, i) => 0xa0 + i);

export const BASE_BINDING: ProofBinding = {
  nonce: '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff',
  walletAddress: 'CBQHNAXSI55GX2GN6D67GK7BHVPSLJUGZQEU7WJ5LKR5PNUCGLIMAO4K',
  contractId: 'CAAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQC526',
  networkPassphrase: 'Test SDF Network ; September 2015',
  ledgerExpiry: 1_500_000,
};

export const OTHER_CONTRACT = 'CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC';

export function claimsFor(publicKey: Uint8Array, overrides: Partial<KycClaims> = {}): KycClaims {
  return {
    schemaVersion: SCHEMA_VERSION,
    issuerId: issuerIdFromPublicKey(publicKey),
    revocationIndex: 4242,
    issuedAt: 1767225600,
    expiresAt: 1782950400,
    subjectBinding: '3d1f2b6a9c8e4705b1d2c3a4f5e6978899aabbccddeeff001122334455667788',
    over18: true,
    over21: true,
    notSanctioned: true,
    notPep: true,
    jurisdictionOk: true,
    livenessOk: true,
    ...overrides,
  };
}

export interface Fixture {
  readonly issuer: IssuerKeyPair;
  readonly other: IssuerKeyPair;
  readonly credential: Credential;
}

let cached: Fixture | undefined;

export async function fixture(): Promise<Fixture> {
  if (cached === undefined) {
    const issuer = await generateIssuerKeyPair(ISSUER_SEED);
    const other = await generateIssuerKeyPair(OTHER_SEED);
    const credential = await issue(claimsFor(issuer.publicKey), issuer.secretKey);
    cached = { issuer, other, credential };
  }
  return cached;
}

export function flipBit(bytes: Uint8Array, offset: number, bit = 0): Uint8Array {
  const copy = Uint8Array.from(bytes);
  copy[offset] = ((copy[offset] ?? 0) ^ (1 << bit)) & 0xff;
  return copy;
}
