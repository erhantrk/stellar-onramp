/**
 *
 * One class for the whole directory, because these failures share a shape: an argument the CALLER
 * built is wrong before any chain is touched (a malformed issuer id, a proof split that cannot
 * happen, a claims bitmap wider than u32). They are all programming or configuration errors, not
 * runtime verdicts — the chain's OWN refusals surface as `KycGateContractError` /
 * `decodeContractErrorCode` from `@stellaronramp/gateway`, and submission/transport failures as
 * `SubmissionError`. Consumers branch on TYPE, never on message text
 * (`apps/gateway-http/src/errors.ts:6-8`).
 */
export class AttestError extends Error {
  override readonly name = 'AttestError';
}

/** A submit/poll/simulate transport failure — never a contract VERDICT. */
export class SubmissionError extends Error {
  override readonly name = 'SubmissionError';
}
