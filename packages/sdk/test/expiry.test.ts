/**
 * `ledgerExpiryFor` clamping edges — the cases the brief calls out by name (margin > window,
 * margin <= 0, sequence near the window). The clamp is the SDK's one piece of owned expiry
 * arithmetic; identity deliberately refuses to own it (binding.ts:29-31).
 */

import { describe, expect, it } from 'vitest';

import {
  DEFAULT_EXPIRY_MARGIN_LEDGERS,
  ExpiryError,
  ledgerExpiryFor,
  recordExpiresAtFor,
} from '../src/index.js';

import { MAX_EXPIRY_HORIZON } from '@stellaronramp/gateway';
import { PROOF_MAX_WINDOW } from '@stellaronramp/identity';

function staticSource(sequence: number): { getLatestLedger: () => Promise<{ sequence: number }> } {
  return { getLatestLedger: async () => ({ sequence }) };
}

describe('ledgerExpiryFor', () => {
  it('the default margin is ~1 h of ledgers and matches demo.ts:1460', () => {
    expect(DEFAULT_EXPIRY_MARGIN_LEDGERS).toBe(720);
  });

  it('a normal margin lands at seq + margin', async () => {
    await expect(ledgerExpiryFor(staticSource(4_195_453))).resolves.toBe(4_195_453 + 720);
  });

  it('an explicit margin is honoured when inside the window', async () => {
    await expect(ledgerExpiryFor(staticSource(100), 5000)).resolves.toBe(5100);
  });

  it(`CLAMPS a margin wider than PROOF_MAX_WINDOW (${PROOF_MAX_WINDOW}) down to the window`, async () => {
    const seq = 7_777_777;
    // +1M ledgers ≈ 58 days — a wish the contract will never grant; narrowed to the maximum.
    await expect(ledgerExpiryFor(staticSource(seq), 1_000_000)).resolves.toBe(seq + PROOF_MAX_WINDOW);
  });

  it('the clamp lands exactly AT the contract boundary, not one past it', async () => {
    const result = await ledgerExpiryFor(staticSource(12), 999_999);
    expect(result - 12).toBe(PROOF_MAX_WINDOW);
  });

  it.each([-1, 0, -720, 1.5, Number.NaN])(
    'refuses a non-positive or non-integer margin (%s)',
    async (margin) => {
      // NaN fails the Number.isInteger gate too.
      await expect(ledgerExpiryFor(staticSource(10), margin as number)).rejects.toThrow(ExpiryError);
    },
  );

  it('refuses an unusable SEQUENCE from the source rather than poisoning later u32 conversions', async () => {
    await expect(ledgerExpiryFor(staticSource(Number.NaN))).rejects.toThrow(ExpiryError);
    await expect(ledgerExpiryFor(staticSource(12.5))).rejects.toThrow(ExpiryError);
    await expect(ledgerExpiryFor(staticSource(-1))).rejects.toThrow(ExpiryError);
  });
});

describe('recordExpiresAtFor', () => {
  // refuses `expires_at < seq` (Expired) and `expires_at - seq > MAX_EXPIRY_HORIZON`
  // (ExpiryTooFar) at contracts/kyc-gate/src/lib.rs:1081-1087. These tests assert against the
  // SOURCE's sequence, never wall-clock time.
  it('dates the record in ledger units from the source sequence, uncapped when sane', async () => {
    expect(await recordExpiresAtFor(staticSource(4_200_000), 86_400)).toBe(
      4_200_000 + 86_400,
    );
  });

  it('never dates a record at or behind the current sequence', async () => {
    const expiresAt = await recordExpiresAtFor(staticSource(4_200_000), 1);
    expect(expiresAt).toBeGreaterThan(4_200_000); // Expired (#12) is unreachable by construction
  });

  it('caps the lead at MAX_EXPIRY_HORIZON — the widest value ExpiryTooFar still accepts', async () => {
    // lib.rs refuses `expires_at - seq > MAX` and ACCEPTS equality, so == horizon must survive.
    expect(await recordExpiresAtFor(staticSource(7), 10_000_000_000)).toBe(7 + MAX_EXPIRY_HORIZON);
    expect(await recordExpiresAtFor(staticSource(7), MAX_EXPIRY_HORIZON)).toBe(
      7 + MAX_EXPIRY_HORIZON,
    );
  });

  it.each([0, -5, Number.NaN, 86_400.5])('refuses a non-positive or fractional lead (%s)', async (ledgers) => {
    await expect(recordExpiresAtFor(staticSource(1), ledgers as number)).rejects.toThrow(ExpiryError);
  });
});
