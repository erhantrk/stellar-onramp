/**
 * `ledgerExpiryFor` — the SDK's one piece of owned expiry arithmetic.
 *
 * `packages/identity` deliberately makes NO network calls and therefore cannot pick a
 * `ledgerExpiry`: `binding.ts:29-31` states the clamp is NOT in `assertValidBinding` because that
 * function is a pure syntactic check with no ledger view, so a caller choosing `ledgerExpiry`
 * `must()`; this module is that clamp as a library, because every SDK consumer would otherwise
 * re-derive it (and the first one to skip it learns about `ExpiryTooFar` (#13) from the chain
 * after deriving a 400-byte proof for nothing).
 *
 * WHY THE CAP EXISTS AT ALL (`demo.ts:1457-1459`, kept verbatim in spirit): the contract caps
 * `ledger_expiry - current_ledger` at `PROOF_MAX_WINDOW` (17,280, ~1 day) and refuses a wider one
 * with `ExpiryTooFar`; the cap is there because the spent-nonce tombstone is TEMPORARY storage,
 * and a proof still fresh after its tombstone is evicted is replayable again.
 */

import { PROOF_MAX_WINDOW } from '@stellaronramp/identity';
import { MAX_EXPIRY_HORIZON } from '@stellaronramp/gateway';

export class ExpiryError extends Error {
  override readonly name = 'ExpiryError';
}

/**
 * enough that a holder's submission is not a race against the next ledger; short enough that the
 * proof dies hours before its tombstone could.
 */
export const DEFAULT_EXPIRY_MARGIN_LEDGERS = 720;

/**
 * The narrowest possible view of a Soroban RPC client: "give me the current ledger sequence".
 * `rpc.Server` from `@stellar/stellar-sdk` satisfies this structurally; tests satisfy it with a
 * stub. Narrow on purpose — identity takes no network dependency, and this package should take no
 * MORE of one than the one call it actually needs.
 */
export interface LatestLedgerSource {
  getLatestLedger(): Promise<{ sequence: number }>;
}

/**
 * against `PROOF_MAX_WINDOW`.
 *
 * CLAMP, NOT THROW, on an over-wide margin. A caller asking for more validity than the contract
 * can ever accept has made a wish, not an error; narrowing it hands back the most the contract
 * accepts instead of refusing the whole flow. The clamp is loud by construction — the returned
 * value simply stops at `seq + PROOF_MAX_WINDOW` — and `margin > PROOF_MAX_WINDOW` remains
 * detectable by comparing the result against the request. What IS refused outright:
 *
 * - `margin <= 0`: an already-expired or zero-margin proof is never what the caller meant; a
 *   negative margin would hand the contract a ledger_expiry in the past.
 * - a non-integer or non-finite sequence from the source (a mocked/buggy client), which would
 *   silently poison every later u32 conversion.
 */
export async function ledgerExpiryFor(
  source: LatestLedgerSource,
  margin: number = DEFAULT_EXPIRY_MARGIN_LEDGERS,
): Promise<number> {
  if (!Number.isInteger(margin) || margin <= 0) {
    throw new ExpiryError(
      `expiry margin must be a positive integer number of ledgers, got ${String(margin)}`,
    );
  }
  const { sequence } = await source.getLatestLedger();
  if (!Number.isSafeInteger(sequence) || sequence < 0) {
    throw new ExpiryError(`ledger source returned an unusable sequence: ${String(sequence)}`);
  }
  return sequence + Math.min(margin, PROOF_MAX_WINDOW);
}

/**
 * The RECORD's `expires_at`, in LEDGER-SEQUENCE units — the same clock the contract checks it
 * against: `attest_bbs` refuses `expires_at < seq` with `Expired` and `expires_at - seq >
 * MAX_EXPIRY_HORIZON` with `ExpiryTooFar` (`contracts/kyc-gate/src/lib.rs:1081-1087`, mirrored on
 * ~1.79e9 minus a ~4.2M ledger is far beyond the horizon — and the first revision of this helper
 * shipped exactly that bug, green suite and all (its tests asserted the helper against its own
 * units, and the live-check script bypassed it with a literal `seq + 100_000`). Both harnesses
 *
 * to the binding's `ledgerExpiry` was considered and REJECTED as incoherent — ~1-day proof
 * freshness vs ~90-day record lifetime; do not re-open). This helper only caps the record's lead
 * over the current ledger at `MAX_EXPIRY_HORIZON` so it can never be refused on submission.
 */
export async function recordExpiresAtFor(
  source: LatestLedgerSource,
  ledgersAhead: number,
): Promise<number> {
  if (!Number.isInteger(ledgersAhead) || ledgersAhead <= 0) {
    throw new ExpiryError(
      `record lifetime must be a positive integer number of ledgers, got ${String(ledgersAhead)}`,
    );
  }
  const { sequence } = await source.getLatestLedger();
  if (!Number.isSafeInteger(sequence) || sequence < 0) {
    throw new ExpiryError(`ledger source returned an unusable sequence: ${String(sequence)}`);
  }
  // Exactly the contract's own bound: `expires_at - seq > MAX_EXPIRY_HORIZON` refuses, so capping
  // the lead AT the horizon is the widest value the chain accepts.
  return sequence + Math.min(ledgersAhead, MAX_EXPIRY_HORIZON);
}
