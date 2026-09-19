/**
 * The KYC provider seam: whatever verified the person returns a `KycStatus`, and the claim
 * derivation turns it into booleans. Nothing downstream of `deriveClaims` sees the status.
 */

export const REVIEW_ANSWERS = ['approved', 'rejected', 'pending'] as const;
export type ReviewAnswer = (typeof REVIEW_ANSWERS)[number];

/** What a provider reports about an applicant. Personal fields are read once, in memory. */
export interface KycStatus {
  readonly provider: string;
  readonly providerRefId: string;
  readonly answer: ReviewAnswer;
  readonly dateOfBirth?: string;
  readonly residenceCountry?: string;
  readonly sanctionsHit?: boolean;
  readonly pepHit?: boolean;
  readonly livenessPassed?: boolean;
  readonly documentNumber?: string;
  readonly fullName?: string;
}

/** The six booleans that travel into the credential. */
export interface ClaimSet {
  readonly over18: boolean;
  readonly over21: boolean;
  readonly notSanctioned: boolean;
  readonly notPep: boolean;
  readonly jurisdictionOk: boolean;
  readonly livenessOk: boolean;
}

export class KycProviderError extends Error {
  override readonly name = 'KycProviderError';
  readonly provider: string;
  constructor(provider: string, message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.provider = provider;
  }
}

export interface KycProvider {
  readonly id: string;
  fetchStatus(providerRefId: string): Promise<KycStatus>;
  deriveClaims(status: KycStatus, at: Date): ClaimSet;
}
