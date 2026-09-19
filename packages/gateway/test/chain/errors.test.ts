/**
 * The error-code map, pinned against the `#[contracterror]` enum in
 * `contracts/kyc-gate/src/lib.rs`, and the decoder that pulls a number back out of an
 * RPC failure.
 *
 * Clients decode BY NUMBER — the names never cross the wire — so a code added on the Rust side
 * without a code added here must be a red test rather than a mystery in production. 8 is retired
 */

import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import {
  KYC_GATE_ERRORS,
  KycGateContractError,
  RETRIABLE_ERROR_CODES,
  decodeContractErrorCode,
  isKycGateError,
  isRetriableContractError,
  kycGateErrorName,
} from '../../src/chain/errors.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const LIB_RS = join(HERE, '..', '..', '..', '..', 'contracts', 'kyc-gate', 'src', 'lib.rs');
const SOURCE = readFileSync(LIB_RS, 'utf8');

/** Parse the `pub enum Error { Name = N, ... }` body that follows `#[contracterror]`. */
function rustErrorEnum(): Record<string, number> {
  const start = SOURCE.indexOf('#[contracterror]');
  expect(start).toBeGreaterThan(-1);
  const open = SOURCE.indexOf('pub enum Error {', start);
  expect(open).toBeGreaterThan(-1);
  const close = SOURCE.indexOf('\n}', open);
  expect(close).toBeGreaterThan(open);
  const body = SOURCE.slice(open, close);
  const out: Record<string, number> = {};
  for (const m of body.matchAll(/^\s*([A-Z][A-Za-z0-9]*)\s*=\s*([0-9]+)\s*,/gm)) {
    const name = m[1];
    const num = m[2];
    if (name === undefined || num === undefined) continue;
    out[name] = Number.parseInt(num, 10);
  }
  return out;
}

describe('the error map matches the contract, in both directions', () => {
  const rust = rustErrorEnum();

  it('parsed a plausible enum out of lib.rs at all', () => {
    expect(Object.keys(rust).length).toBe(12);
    expect(rust['RevocationEpochMismatch']).toBe(15);
  });

  it('every Rust variant is present here with the same number', () => {
    for (const [name, code] of Object.entries(rust)) {
      expect(KYC_GATE_ERRORS[name as keyof typeof KYC_GATE_ERRORS], `missing ${name}`).toBe(code);
    }
  });

  it('every entry here exists in the Rust enum — no invented codes', () => {
    for (const [name, code] of Object.entries(KYC_GATE_ERRORS)) {
      expect(rust[name], `${name} is not a kyc-gate error`).toBe(code);
    }
  });

  it('is exactly the twelve live codes, with no 300-399 collision', () => {
    const codes = Object.values(KYC_GATE_ERRORS).sort((a, b) => a - b);
    expect(codes).toEqual([1, 2, 3, 4, 5, 6, 7, 10, 12, 13, 14, 15]);
    expect(codes.some((c) => c >= 300 && c <= 399)).toBe(false);
  });

  it('maps numbers back to names, and reports an unknown number rather than throwing', () => {
    expect(kycGateErrorName(15)).toBe('RevocationEpochMismatch');
    expect(kycGateErrorName(3)).toBe('NoClaimRecord');
    expect(kycGateErrorName(16)).toBeUndefined();
    expect(kycGateErrorName(8)).toBeUndefined();
    expect(kycGateErrorName(0)).toBeUndefined();
  });
});

describe('decoding a code out of whatever the RPC layer threw', () => {
  it('reads the shape the deployed contract actually produces', () => {
    expect(decodeContractErrorCode(new Error('HostError: Error(Contract, #15)'))).toBe(15);
    expect(decodeContractErrorCode('HostError: Error(Contract, #3)')).toBe(3);
    expect(decodeContractErrorCode({ error: 'host invocation failed: Error(Contract, #14)' })).toBe(14);
  });

  it('tolerates whitespace variation after the comma', () => {
    expect(decodeContractErrorCode('Error(Contract,#15)')).toBe(15);
    expect(decodeContractErrorCode('Error(Contract,   #15)')).toBe(15);
  });

  it('#30..#39 DO NOT alias onto #3 — the closing paren is part of the match', () => {
    for (const n of [30, 31, 33, 39, 130, 315]) {
      expect(decodeContractErrorCode(`Error(Contract, #${n})`)).toBe(n);
    }
    // The specific confusion this guards: a decoder matching `#3` without the paren would read
    // NoClaimRecord out of #30 and sign at a guessed epoch 0.
    expect(decodeContractErrorCode('Error(Contract, #30)')).not.toBe(3);
  });

  it('walks the cause chain, because the SDK wraps', () => {
    const inner = new Error('HostError: Error(Contract, #15)');
    const outer = new Error('simulation failed', { cause: inner });
    const outermost = new Error('submit failed', { cause: outer });
    expect(decodeContractErrorCode(outermost)).toBe(15);
  });

  it('survives a cyclic cause chain instead of hanging', () => {
    const a = new Error('a') as Error & { cause?: unknown };
    const b = new Error('b: Error(Contract, #12)') as Error & { cause?: unknown };
    a.cause = b;
    b.cause = a;
    expect(decodeContractErrorCode(a)).toBe(12);
  });

  it('returns undefined for anything that is not a contract error', () => {
    for (const notOne of [
      undefined,
      null,
      '',
      new Error('fetch failed'),
      new Error('ETIMEDOUT'),
      new Error('Error(Storage, InvalidAction)'),
      new Error('Error(Contract, #not-a-number)'),
      new Error('#15'),
      { status: 500 },
    ]) {
      expect(decodeContractErrorCode(notOne)).toBeUndefined();
    }
  });

  it('FAILS CLOSED on two different codes in one haystack rather than picking one', () => {
    const ambiguous = new Error('Error(Contract, #15) while recovering Error(Contract, #5)');
    expect(decodeContractErrorCode(ambiguous)).toBeUndefined();
    expect(isRetriableContractError(ambiguous)).toBe(false);
  });

  it('the same code repeated many times is NOT ambiguous', () => {
    const repeated = new Error(
      'Error(Contract, #15)\n  diagnostic: Error(Contract, #15)\n  again: Error(Contract, #15)',
    );
    expect(decodeContractErrorCode(repeated)).toBe(15);
  });

  it('isKycGateError names the code', () => {
    const e = new Error('Error(Contract, #3)');
    expect(isKycGateError(e, 'NoClaimRecord')).toBe(true);
    expect(isKycGateError(e, 'RevocationEpochMismatch')).toBe(false);
    expect(isKycGateError(new Error('fetch failed'), 'NoClaimRecord')).toBe(false);
  });
});

describe('exactly one refusal is a race, and the rest are verdicts', () => {
  it('RevocationEpochMismatch is the only retriable code', () => {
    expect([...RETRIABLE_ERROR_CODES]).toEqual([KYC_GATE_ERRORS.RevocationEpochMismatch]);
  });

  it.each([
    'SubjectRevoked',
    'StaleAttestation',
    'EmptyClaims',
    'ExpiryTooFar',
    'NonceAlreadyUsed',
    'NoClaimRecord',
    'InvalidProof',
    'UntrustedIssuer',
    'Expired',
    'NotInitialized',
    'AlreadyInitialized',
  ] as const)('%s is NOT retried — an identical retry reproduces it exactly', (name) => {
    const code = KYC_GATE_ERRORS[name];
    expect(RETRIABLE_ERROR_CODES.has(code)).toBe(false);
    expect(isRetriableContractError(new Error(`Error(Contract, #${code})`))).toBe(false);
  });

  it('a transport failure is not retriable as a contract error either', () => {
    // It may well be worth retrying at the transport layer; it is NOT a #15 re-sign, which is the
    // only thing this predicate answers.
    expect(isRetriableContractError(new Error('fetch failed'))).toBe(false);
  });
});

describe('KycGateContractError', () => {
  it('carries the number, the name and the original throw', () => {
    const cause = new Error('HostError: Error(Contract, #15)');
    const e = new KycGateContractError(15, 'attest_bbs(GABC…)', cause);
    expect(e.code).toBe(15);
    expect(e.errorName).toBe('RevocationEpochMismatch');
    expect(e.message).toContain('#15');
    expect(e.message).toContain('RevocationEpochMismatch');
    expect(e.message).toContain('attest_bbs(GABC…)');
    expect(e.cause).toBe(cause);
    expect(e).toBeInstanceOf(Error);
  });

  it('still reports an unknown future code by number', () => {
    const e = new KycGateContractError(99, 'attest_bbs');
    expect(e.code).toBe(99);
    expect(e.errorName).toBeUndefined();
    expect(e.message).toContain('#99');
  });
});
