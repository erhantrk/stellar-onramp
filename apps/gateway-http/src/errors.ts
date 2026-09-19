/**
 * The transport's error taxonomy: one `HttpError{status, code, retriable}` plus a single
 * `toHttpError(err)` that maps the library's TYPED errors onto HTTP statuses and machine codes
 *
 * THE APP NEVER REACHES INTO THE LIBRARY'S ERROR MESSAGE STRINGS. It maps on TYPE. A
 * `WebhookReplayError` whose `reason === 'duplicate'` is an idempotent ack (200), a stale one is
 * 400, and the message the caller sees is a transport-shaped envelope, not the library's operator
 * prose. Nothing in this file, and nothing that writes an HTTP response, ever echoes a webhook raw
 */

import {
  EpochReadError,
  IssuanceError,
  KycGateContractError,
  KycProviderError,
} from '@stellaronramp/gateway';

/** Every HTTP error carries a machine code for alert rules and a retriable flag for the caller. */
export interface HttpErrorShape {
  readonly status: number;
  readonly code: string;
  readonly retriable: boolean;
}

export class HttpError extends Error implements HttpErrorShape {
  override readonly name = 'HttpError';
  readonly status: number;
  readonly code: string;
  readonly retriable: boolean;

  constructor(shape: HttpErrorShape, message?: string) {
    super(message ?? shape.code);
    this.status = shape.status;
    this.code = shape.code;
    this.retriable = shape.retriable;
  }
}

/** Thrown by the `Unimplemented*` fail-closed seams and mapped to 501. Named so a test can assert. */
export class UnimplementedError extends Error {
  override readonly name = 'UnimplementedError';
  constructor(what: string) {
    super(`${what} is NOT IMPLEMENTED. The gateway build run defines this surface as a fail-closed ` +
      'seam; a production deploy that reaches it gets 501, never a silent fallback to a weaker path.');
  }
}

/**
 * 401 — the request carried no usable credential for the route's auth mode: none at all, a
 * malformed one, or one that failed verification (bad signature, expired, foreign issuer/audience).
 *
 * The machine code is DISTINCT from the webhook's 401 (`webhook_verification_failed`): that one
 * means "a provider delivery failed HMAC", this one means "an SDK caller is not authenticated".
 * Alert rules triage on the code, so collapsing them would merge two unrelated incident classes.
 *
 * THE MESSAGE IS A FIXED STRING and must stay one: it never echoes the presented Authorization
 * header, the token payload, or WHY verification failed — a rejection reason is a probing oracle,
 * and a token payload can carry PII (same rule as the webhook bodies above).
 */
export class UnauthorizedError extends Error {
  override readonly name = 'UnauthorizedError';
  constructor() {
    super('authentication required');
  }
}

/**
 * 403 — the credential was VALID but is not SUFFICIENT for this route: a session JWT offered to an
 * admin route, an admin API key offered to a session route. Distinct from 401 on purpose: the
 * caller is authenticated and should stop re-sending different secrets (an alert-rule difference),
 * and distinct from every other code so the envelope stays machine-triageable. Fixed message, same
 * no-echo rule as above.
 */
export class ForbiddenError extends Error {
  override readonly name = 'ForbiddenError';
  constructor() {
    super('insufficient permissions');
  }
}

/**
 * 403 `subject_mismatch` — the SUBJECT BINDING refusal, the founding lesson of this repo
 * enforced at the SEP-12 surface: a validly-signed SEP-10 token whose `sub` does not equal the
 * account the request ADDRESSES (query `account`, path `{account}`, or body `account`) is
 * refused LOUDLY with its OWN machine code — never treated as anonymous, never fallen through to
 * fixed string: it names no account and no token content — the DISTINCT code exists so alert
 * rules can separate "probing someone else's account" from ordinary bad credentials.
 *
 * Enforced in src/handlers/sep12.ts on EVERY SEP-12 cell; possession of a valid anchor token
 * alone authorizes nothing.
 */
export class SubjectMismatchError extends Error {
  override readonly name = 'SubjectMismatchError';
  constructor() {
    super('token subject does not match the addressed account');
  }
}

/**
 * The single mapping. `unknown` in, `HttpError` out — a handler throws, the dispatcher maps.
 *
 * The one non-error result in the table is a `WebhookReplayError` with `reason: 'duplicate'`, which
 * becomes status 200: the event was already processed, so an idempotent ack IS the correct response
 * every other result, so the envelope shape is identical — a caller cannot tell an ack from a
 * success by status alone, which is exactly the idempotency the provider expects.
 */
export function toHttpError(err: unknown): HttpError {
  if (err instanceof HttpError) return err;
  if (err instanceof KycProviderError) {
    return new HttpError({ status: 400, code: 'kyc_provider_error', retriable: false },
      'KYC provider refused the request');
  }
  if (err instanceof IssuanceError) {
    return new HttpError({ status: 400, code: 'issuance_error', retriable: false },
      'credential issuance refused');
  }
  if (err instanceof KycGateContractError || err instanceof EpochReadError) {
    return new HttpError({ status: 503, code: 'chain_unavailable', retriable: true },
      'the on-chain gateway is refusing or unreachable');
  }
  if (err instanceof UnimplementedError) {
    return new HttpError({ status: 501, code: 'not_implemented', retriable: false }, err.message);
  }
  if (err instanceof UnauthorizedError) {
    return new HttpError({ status: 401, code: 'unauthorized', retriable: false }, err.message);
  }
  if (err instanceof ForbiddenError) {
    return new HttpError({ status: 403, code: 'forbidden', retriable: false }, err.message);
  }
  if (err instanceof SubjectMismatchError) {
    return new HttpError({ status: 403, code: 'subject_mismatch', retriable: false }, err.message);
  }
  if (isSep12CustomerNotFound(err)) {
    return new HttpError({ status: 404, code: 'not_found', retriable: false }, 'no such customer');
  }
  if (isSessionNotApproved(err)) {
    return new HttpError({ status: 409, code: 'session_not_approved', retriable: false },
      'the session is not approved; a credential cannot be issued for it yet');
  }
  // Unknown. Never leak the raw message (it may carry PII or a webhook body prefix) — the envelope
  // message is the fixed string below; the operator-facing detail goes nowhere.
  return new HttpError({ status: 500, code: 'internal_error', retriable: true },
    'internal error');
}

/** Duck-type check kept local so errors.ts does not import the seams. */
function isSessionNotApproved(err: unknown): boolean {
  return (
    typeof err === 'object' &&
    err !== null &&
    'name' in err &&
    (err as { name?: unknown }).name === 'SessionNotApprovedError'
  );
}

/** Same duck-type discipline for the SEP-12 store's unknown-account refusal. */
function isSep12CustomerNotFound(err: unknown): boolean {
  return (
    typeof err === 'object' &&
    err !== null &&
    'name' in err &&
    (err as { name?: unknown }).name === 'Sep12CustomerNotFoundError'
  );
}
