/**
 * Offline fakes for every chain seam. NOT a test file (the vitest `include` is
 * `test/ ** /*.test.ts`), so nothing here is collected as a suite.
 *
 * These exist so that NO unit test in this package touches the network. `npx vitest run` from the
 * repo root must never hit the wire; every seam a test needs is faked here.
 */

import type { GateSimulator, LedgerClock } from '../../src/chain/epoch.js';

/** The shape `claim_record` decodes from, with the Rust snake_case keys the ScMap actually carries. */
export function rawClaimRecord(over: Partial<Record<string, unknown>> = {}): Record<string, unknown> {
  return {
    claims: 5,
    expires_at: 4_289_411,
    issuer_id: new Uint8Array(32),
    issued_at: 4_189_413,
    revocation_epoch: 0,
    revocation_index: 4711,
    ...over,
  };
}

/**
 * The EXACT string the deployed contract produces for `NoClaimRecord`, measured against
 * Note it contains `Error(Contract, #3)` TWICE — once in the header and once in the diagnostic event —
 * which is why the decoder must treat a repeated identical code as unambiguous.
 */
export const LIVE_NO_CLAIM_RECORD_ERROR =
  'claim_record(GAOS3CYFTRFSBSVN4GORA3PSOIJICMMHDCRRQEOQDS42ASC4V52BXPE3) simulation failed: ' +
  'HostError: Error(Contract, #3)\n\nEvent log (newest first):\n' +
  '   0: [Diagnostic Event] contract:CABAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAFNSZ, ' +
  'topics:[error, Error(Contract, #3)], data:"escalating Ok(ScErrorType::Contract) frame-exit to Err"\n' +
  '   1: [Diagnostic Event] topics:[fn_call, CABAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAFNSZ, ' +
  'claim_record], data:GAOS3CYFTRFSBSVN4GORA3PSOIJICMMHDCRRQEOQDS42ASC4V52BXPE3';

/** A simulator that always rejects with the given value. */
export function rejectingSimulator(err: unknown): GateSimulator {
  return {
    async simulateClaimRecord() {
      throw err;
    },
  };
}

/** A simulator that always resolves the given raw value. */
export function resolvingSimulator(raw: unknown): GateSimulator {
  return {
    async simulateClaimRecord() {
      return raw;
    },
  };
}

/**
 * A simulator whose answer CHANGES between calls, which is how the epoch race is reproduced offline:
 * read 1 sees epoch 0, the submission is refused with #15, read 2 sees epoch 1.
 */
export class ScriptedSimulator implements GateSimulator {
  readonly #answers: readonly (unknown | Error)[];
  #calls = 0;

  constructor(answers: readonly (unknown | Error)[]) {
    this.#answers = answers;
  }

  get calls(): number {
    return this.#calls;
  }

  async simulateClaimRecord(): Promise<unknown> {
    const answer = this.#answers[Math.min(this.#calls, this.#answers.length - 1)];
    this.#calls += 1;
    if (answer instanceof Error) throw answer;
    return answer;
  }
}

/** A fixed ledger clock. Every unit test pins the ledger so `expires_at` is deterministic. */
export function fixedLedger(sequence: number): LedgerClock {
  return {
    async latestLedger() {
      return sequence;
    },
  };
}

/** A contract refusal in the shape the RPC layer delivers one. */
export function contractError(code: number): Error {
  return new Error(`HostError: Error(Contract, #${code})`);
}

/** Well-formed testnet addresses used across the suite. */
export const TEST_SUBJECT = 'GAOS3CYFTRFSBSVN4GORA3PSOIJICMMHDCRRQEOQDS42ASC4V52BXPE3';
export const TEST_GATE = 'CABAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAFNSZ';
