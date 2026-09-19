/**
 * The provider-side applicant seam. `POST /v1/session` creates the KYC provider's applicant for
 * the session so the provider's later verdict can be joined back to it. The demo server injects
 * an in-process mock; a real deployment injects the provider's API client.
 */

import { UnimplementedError } from '../errors.js';

export interface CreateApplicantRequest {
  readonly walletCAddr: string;
  readonly sessionId: string;
}

export interface KycApplicantCreator {
  /** Create the provider-side applicant; resolves with the provider's reference id. */
  create(req: CreateApplicantRequest): Promise<string>;
}

export class UnimplementedKycApplicantCreator implements KycApplicantCreator {
  async create(_req: CreateApplicantRequest): Promise<string> {
    throw new UnimplementedError('KYC applicant creation');
  }
}
