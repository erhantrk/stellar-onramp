/**
 *
 * Creates and stores `session_id -> wallet C-address` in the in-memory `SessionStore` FIRST, so
 * even when the fail-closed auth seams refuse (the default is 501), the session write has happened
 * and session-JWT issuance. With the default `Unimplemented*` seams both throw 501 and the route
 * answers 501 — the client gets no token, which is the correct fail-closed outcome for an auth
 * surface that does not exist yet.
 *
 * CONFORMANCE DECISIONS ON THE WIRE SHAPE, stated here rather than left silent:
 *
 *   * REQUEST FIELDS ARE SNAKE_CASE per spec :899 (`wallet_c_addr`, `chain_id`). The earlier
 *     camelCase `walletCAddr` spelling was this repo's invention and is refused now; nothing
 *     external consumes this endpoint yet (`packages/sdk` never parses it — verified before the
 *     rename), so conformance wins over compatibility.
 *   * `chain_id` is REQUIRED and shape-checked (non-empty string, bounded, no control characters)
 *     but is NOT PERSISTED: spec pins the store to `(session_id → wallet_c_addr)` ONLY. Its role
 *     today is client-intent declaration and forward compatibility; silently ignoring a malformed
 *     one would let half-formed requests look well-formed, which is why it is validated at all.
 *     closed the gap where it was accepted as any non-empty string beside a validated chain_id).
 *     Unlike chain_id it is PERSISTED and becomes load-bearing three ways: the session store key's
 *     wallet, the session JWT's §5.2-pinned `sub`, and eventually the credential subject-binding
 *     input (sha256(wallet C-address ‖ salt)). A junk value entering here would propagate into
 *     all three, so issuance refuses it at the door (assertCAddress, src/g-address.ts).
 *   * RESPONSE FIELD NAMES follow spec :899 exactly. DEVIATION IN MEANING, DOCUMENTED: the value
 *     SDK→gateway credential minted by `Es256SessionJwtIssuer`) — NOT an access token issued by
 *     name or both tokens get distinct fields — that decision belongs to that run, and this
 *     docblock is where it will be argued. The old undocumented `applicant_id` field is GONE
 *   * DPoP proof-of-possession (§5.2 end-state) is NOT part of this token; the absence is
 *     documented where the token contract lives — see seams/session-jwt.ts.
 */

import { assertCAddress } from '../g-address.js';
import { writeJson, asRecord } from '../middleware.js';
import { SESSION_JWT_MAX_TTL_SECONDS as SESSION_JWT_TTL_SECONDS } from '../seams/session-jwt.js';
import { HttpError } from '../errors.js';
import type { ResolvedAppConfig, RouteHandler } from '../types.js';

/** Bound for `chain_id`: long enough for a CAIP-2 id or a network passphrase, short enough to log. */
const MAX_CHAIN_ID_CHARS = 128;

/**
 * `chain_id` shape check: present, a non-empty string, bounded, and free of control characters.
 * The charset is left WIDE on purpose — plausible values range from `'testnet'` through CAIP-2 ids
 * to Stellar passphrases containing spaces and semicolons — so only genuinely malformed shapes
 * (absent, wrong type, empty, control bytes) are refused.
 */
function requireChainId(body: Record<string, unknown>): string {
  const v = body['chain_id'];
  if (v === undefined || v === null) {
    throw new HttpError({ status: 400, code: 'missing_field', retriable: false },
      'missing or invalid "chain_id"');
  }
  // eslint-disable-next-line no-control-regex -- refusing control bytes is the point
  if (typeof v !== 'string' || v.length === 0 || v.length > MAX_CHAIN_ID_CHARS || /[\u0000-\u001F\u007F]/.test(v)) {
    throw new HttpError({ status: 400, code: 'invalid_field', retriable: false },
      `"chain_id" must be a non-empty string of at most ${MAX_CHAIN_ID_CHARS} characters without control characters`);
  }
  return v;
}

export function sessionHandler(config: ResolvedAppConfig): RouteHandler {
  return async (ctx) => {
    const body = asRecord(ctx.json);
    const walletCAddr = assertCAddress(body['wallet_c_addr'], 'wallet_c_addr');
    // Validated and deliberately dropped: see the store-contract note in the module docblock.
    requireChainId(body);
    const now = config.now();

    const sessionId = await config.sessionStore.create(walletCAddr, now);
    // Fail-closed auth seams: applicant creation + JWT issuance throw 501 by default.
    // this session — that join is what the webhook's approval path looks up (see the seam
    // docblock for why a wallet-address-only input cannot work).
    await config.kycApplicantCreator.create({ walletCAddr, sessionId });
    const expiresAt = now + SESSION_JWT_TTL_SECONDS;
    const sessionToken = await config.sessionJwtIssuer.issue({
      sessionId,
      walletCAddr,
      issuedAt: now,
      expiresAt,
    });

    // the module docblock, never silent.
    writeJson(ctx.response, 201, {
      session_id: sessionId,
      session_token: sessionToken,
      expires_at: expiresAt,
    });
  };
}
