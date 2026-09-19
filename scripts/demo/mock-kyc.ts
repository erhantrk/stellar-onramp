/**
 * An in-process mock of the KYC provider.
 *
 * The demo has no provider account, so instead of faking the RESULT it fakes the PROVIDER: the
 * verdict, and everything downstream (claim derivation, credential issuance, the proof, the
 * on-chain write) runs unchanged against the real `KycProvider` seam.
 *
 * Personal data lives here only for the duration of one run; `forgetApplicant` drops it.
 */

import { deriveClaimSet } from '@stellaronramp/gateway';
import type { ClaimSet, KycProvider, KycStatus, ReviewAnswer } from '@stellaronramp/gateway';

export const MOCK_PROVIDER_ID = 'mock-kyc';

/** What the wizard collects and the mock provider "verifies". */
export interface Applicant {
  readonly givenName: string;
  readonly familyName: string;
  /** `YYYY-MM-DD`. */
  readonly dateOfBirth: string;
  readonly documentNumber: string;
  /** ISO 3166-1 alpha-2. */
  readonly residenceCountry: string;
}

/** The default applicant, used when a caller supplies none. */
export const DEFAULT_APPLICANT: Applicant = Object.freeze({
  givenName: 'Amara',
  familyName: 'Osei',
  dateOfBirth: '1994-03-11',
  documentNumber: 'P<GBR9482715',
  residenceCountry: 'DE',
});

export interface MockKyc extends KycProvider {
  /** The seam `POST /v1/session` calls to create the provider-side applicant. */
  readonly applicantCreator: {
    create(req: { walletCAddr: string; sessionId: string }): Promise<string>;
  };
  /** Record the provider's verdict and the applicant's attributes for one run. */
  decide(applicantId: string, answer: 'GREEN' | 'RED', applicant?: Applicant): void;
  /** The applicant id the creator assigned to a session id. */
  applicantForSession(sessionId: string): string | undefined;
  /** Drop the applicant's personal data once its run is over. */
  forgetApplicant(applicantId: string): void;
}

export function createMockKyc(): MockKyc {
  let counter = 0;
  const sessionToApplicant = new Map<string, string>();
  const applicants = new Map<string, { answer: ReviewAnswer; applicant: Applicant }>();

  return {
    id: MOCK_PROVIDER_ID,

    applicantCreator: {
      async create(req: { walletCAddr: string; sessionId: string }): Promise<string> {
        counter += 1;
        const applicantId = `applicant-${counter}`;
        sessionToApplicant.set(req.sessionId, applicantId);
        return applicantId;
      },
    },

    decide(applicantId, answer, applicant = DEFAULT_APPLICANT): void {
      applicants.set(applicantId, {
        answer: answer === 'GREEN' ? 'approved' : 'rejected',
        applicant,
      });
    },

    applicantForSession(sessionId: string): string | undefined {
      return sessionToApplicant.get(sessionId);
    },

    forgetApplicant(applicantId: string): void {
      applicants.delete(applicantId);
    },

    async fetchStatus(providerRefId: string): Promise<KycStatus> {
      const entry = applicants.get(providerRefId);
      if (entry === undefined) {
        return { provider: MOCK_PROVIDER_ID, providerRefId, answer: 'pending' };
      }
      const a = entry.applicant;
      return {
        provider: MOCK_PROVIDER_ID,
        providerRefId,
        answer: entry.answer,
        dateOfBirth: a.dateOfBirth,
        residenceCountry: a.residenceCountry,
        sanctionsHit: false,
        pepHit: false,
        livenessPassed: true,
        documentNumber: a.documentNumber,
        fullName: `${a.givenName} ${a.familyName}`,
      };
    },

    deriveClaims(status: KycStatus, at: Date): ClaimSet {
      return deriveClaimSet(status, at);
    },
  };
}
