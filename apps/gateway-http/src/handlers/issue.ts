/**
 *
 * TWO gates run before anything is spent, in this order:
 *
 *      without): the route is `auth: 'session'`, so the verified token subject is the wallet
 *      named session belongs to — otherwise a valid session JWT for wallet A could drive issuance
 *      of a victim-bound credential against wallet B's approved session id. Mismatch is the loud
 *      403 `subject_mismatch`, and running it first means a probed foreign session id answers 403
 *      regardless of its approval state, never a 409 describing someone else's session.
 *   2. `SessionStore.assertApproved`: an existing but pending session is refused 409 (an UNKNOWN
 *      id is also 409 — it has no owner, so answering it first leaks nothing).
 *
 * The wallet address comes from the session store, not from the body — the client cannot bind a
 * credential to a wallet it did not onboard. Claims are read from the body as the six booleans;
 * all correctness (subject binding, bitmap, revocation index, signature) lives in the library's
 * `issueKycCredential`. The response carries the serialized credential plus the holder's salt
 * (never persisted by the gateway) and the claim bitmap / revocation index.
 */

import { HttpError } from '../errors.js';
import {
  assertSessionSubjectBinding,
  optionalU32,
  requireString,
  writeJson,
  asRecord,
} from '../middleware.js';
import type { ResolvedAppConfig, RouteHandler } from '../types.js';

import { issueKycCredential } from '@stellaronramp/gateway';
import type { ClaimSet } from '@stellaronramp/gateway';
import { toHex } from '@stellaronramp/identity';

const DEFAULT_CREDENTIAL_LIFETIME_SECONDS = 24 * 60 * 60;

const CLAIM_FIELDS = [
  'over18',
  'over21',
  'notSanctioned',
  'notPep',
  'jurisdictionOk',
  'livenessOk',
] as const;

/** Read the six boolean claims from the body, refusing any non-boolean. */
function readClaimSet(body: Record<string, unknown>): ClaimSet {
  const out: Record<string, boolean> = {};
  for (const field of CLAIM_FIELDS) {
    const v = body[field];
    if (typeof v !== 'boolean') {
      throw new HttpError(
        { status: 400, code: 'invalid_field', retriable: false },
        `"${field}" must be a boolean`,
      );
    }
    out[field] = v;
  }
  return out as unknown as ClaimSet;
}

export function issueHandler(config: ResolvedAppConfig): RouteHandler {
  return async (ctx) => {
    const body = asRecord(ctx.json);
    const sessionId = requireString(body, 'sessionId');

    const session = config.sessionStore.get(sessionId);
    if (session === undefined) {
      // Unknown id: no owner exists, so answering before the gates below leaks nothing.
      throw new HttpError(
        { status: 409, code: 'session_not_approved', retriable: false },
        'the session is not approved',
      );
    }

    // THE ENFORCING LINE — the caller's own token must belong to THIS session's wallet. It runs
    // BEFORE the approval verdict so a probed FOREIGN session id answers 403 subject_mismatch
    // regardless of its state, never a 409 describing someone else's session; and before any
    // claim shaping or issuance spend.
    assertSessionSubjectBinding(ctx, session.walletCAddr);

    // The load-bearing gate. Refuses a not-yet-approved session with 409 before anything is spent.
    config.sessionStore.assertApproved(sessionId);

    const claims = readClaimSet(body);
    const now = config.now();
    const issuedAt = now;
    const expiresAt = optionalU32(body, 'expiresAt') ?? now + DEFAULT_CREDENTIAL_LIFETIME_SECONDS;

    const issued = await issueKycCredential({
      claims,
      walletAddress: session.walletCAddr,
      issuedAt,
      expiresAt,
      issuerSecretKey: config.issuerSecretKey,
      issuerPublicKey: config.issuerPublicKey,
      allocator: config.revocationIndexAllocator,
      provider: 'kyc-provider',
      providerRefId: sessionId,
      subjectId: sessionId,
    });

    writeJson(ctx.response, 201, {
      credential: issued.serialized,
      claim_bitmap: issued.claimBitmap,
      revocation_index: issued.record.revocationIndex,
      subject_binding_salt: toHex(issued.subjectBindingSalt),
    });
  };
}
