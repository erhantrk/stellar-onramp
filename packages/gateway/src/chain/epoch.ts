/**
 *
 * Before signing an attestation OR a revocation the gateway must read the subject's CURRENT
 * `revocation_epoch` off the chain and bind it into the payload. One RPC simulation per signature.
 * `kyc-gate` refuses any signature naming a different epoch with `RevocationEpochMismatch` (#15), and
 * every `revoke()` increments the epoch (saturating). An epoch does not order by TIME, so no sliding
 * window and no retry delay can ever catch up with one: a signature made at epoch N is refused at
 * epoch N+1 forever.
 *
 * ===================================================================================
 * FAIL CLOSED. `NoClaimRecord` (#3) MEANS EPOCH 0. NOTHING ELSE DOES.
 * ===================================================================================
 *
 * `claim_record(subject)` answers `Err(NoClaimRecord)` = contract error #3 for a subject nobody has
 * ever attested or revoked, and that — and ONLY that — means the subject is at epoch 0. A
 * `try { … } catch { return 0 }` around the read turns a transient RPC failure, a request timeout, a
 * wrong contract id, a malformed response and an archived-entry error ALL into a confident "epoch 0".
 * The gateway then signs at an epoch the chain disagrees with, every such signature bounces with #15,
 * and the operator is handed that mystery instead of the RPC error that actually caused it.
 *
 * So {@link readSubjectChainState} discriminates: exactly `#3` -> epoch 0 with no record; anything
 * else, including an ambiguous or undecodable failure, -> THROW, and do not sign.
 * `test/chain/epoch.test.ts` drives each shape through a fake RPC individually.
 *
 * ARCHIVED entries only happens if RPC simulation populated the restore list. Reading the entry
 * directly would work right up to the day the record is archived, and then break with no warning.
 */

import { Account, Address, Contract, TransactionBuilder, rpc, scValToNative } from '@stellar/stellar-sdk';

import { KYC_GATE_ERRORS, KycGateContractError, decodeContractErrorCode } from './errors.js';

/** `lib.rs::ClaimRecord`, decoded. Field names are camelCased here; the ScMap keys on the wire are
 *  the Rust snake_case ones, and {@link decodeClaimRecord} is the only place that knows that. */
export interface ClaimRecord {
  /** Claim bitmap. `0` is a REVOCATION TOMBSTONE, not an attestation — nothing but `revoke` can */
  claims: number;
  /** Ledger sequence at which the record stops being honoured. `check()` is `seq <= expires_at`. */
  expiresAt: number;
  /** BBS+ issuer key id, 32 bytes. */
  issuerId: Uint8Array;
  /** Ledger the record was written at. Audit trail; `check()` ignores it. */
  issuedAt: number;
  /** Revocations this subject has ever had. THE field both signed payloads bind. */
  revocationEpoch: number;
  /**
   *  back by the contract: it is the audit link to the off-chain status list. */
  revocationIndex: number;
}

/** What the gateway needs to know before it signs anything for a subject. */
export interface SubjectChainState {
  subject: string;
  /** The epoch to bind. `0` when {@link record} is `null`. */
  revocationEpoch: number;
  /** `null` iff the contract answered `NoClaimRecord` (#3). */
  record: ClaimRecord | null;
  /** True iff `record.claims === 0`, i.e. the subject carries a revocation tombstone. Signing an
   *  attestation for one is legal (the epoch gate is what orders it) but is a compliance decision,
   *  not a mechanical one — a revoked subject being re-attested is a REINSTATEMENT. */
  revoked: boolean;
}

/**
 * The narrow seam every unit test replaces. ONE method, and it deliberately does not mention ScVal,
 * XDR or the SDK, so a fake is five lines.
 *
 * Contract: resolve the decoded native return value of `claim_record(subject)`, or REJECT. A
 * `NoClaimRecord` refusal MUST be a rejection whose message carries `Error(Contract, #3)` — that is
 * how the deployed contract's failure actually reaches a client, measured against
 */
export interface GateSimulator {
  simulateClaimRecord(subject: string): Promise<unknown>;
}

/**
 * Where "what ledger is it" comes from. Separate from {@link GateSimulator} because a gateway with a
 * ledger-sequence cache or a subscription feed should be able to supply this without also supplying
 * a contract simulator — and because every unit test needs to pin the ledger to a fixed number.
 *
 * {@link SorobanGateSimulator} satisfies both.
 */
export interface LedgerClock {
  latestLedger(): Promise<number>;
}

/** Thrown when the epoch could not be established. The gateway MUST NOT sign after seeing this. */
export class EpochReadError extends Error {
  readonly subject: string;
  constructor(subject: string, detail: string, cause?: unknown) {
    super(
      `refusing to assume revocation_epoch 0 for ${subject}. Only NoClaimRecord (#3) means a subject ` +
        'is at epoch 0; signing at a guessed epoch mints signatures the chain refuses with ' +
        `RevocationEpochMismatch (#15) for a reason nobody can see. Underlying cause: ${detail}`,
    );
    this.name = 'EpochReadError';
    this.subject = subject;
    if (cause !== undefined) this.cause = cause;
  }
}

/** Decode the ScMap `claim_record` returns. Every field is validated: a record that decoded
 *  partially would produce a signature bound to a `NaN` epoch, which `u32be` then rejects far from
 *  the cause. */
export function decodeClaimRecord(raw: unknown): ClaimRecord {
  if (typeof raw !== 'object' || raw === null) {
    throw new TypeError(`claim_record returned ${raw === null ? 'null' : typeof raw}, not a record`);
  }
  const rec = raw as Record<string, unknown>;
  const u32 = (key: string): number => {
    const v = rec[key];
    // both became 0, `true` became 1, `'7'` became 7 and `[7]` became 7. For `revocation_epoch`
    // that is precisely the fail-open this whole module exists to prevent — `scValToNative` maps
    // `ScVal::Void` to `null`, so a foreign contract that happens to export a `claim_record` symbol
    // (the contract-id-typo case named below) could hand back a record that decoded "successfully"
    // at epoch 0. Only a real number or a real bigint is accepted now; a bigint because that is
    // what `scValToNative` returns for wide integer ScVals.
    if (typeof v !== 'number' && typeof v !== 'bigint') {
      // Message deliberately keeps the `is not a u32` wording the pre-existing test pins, and ADDS
      // the not-a-number reason, so the earlier assertion still holds.
      throw new TypeError(
        `claim_record.${key} is not a u32: ${String(v)} — it is ${v === null ? 'null' : typeof v}, ` +
          'not a number, and this decoder refuses to coerce. A coerced field is a signature bound ' +
          'to a guessed value.',
      );
    }
    const n = Number(v);
    if (!Number.isInteger(n) || n < 0 || n > 0xffff_ffff) {
      throw new TypeError(`claim_record.${key} is not a u32: ${String(v)}`);
    }
    return n;
  };
  const issuerRaw = rec['issuer_id'];
  if (!(issuerRaw instanceof Uint8Array) || issuerRaw.length !== 32) {
    throw new TypeError(
      `claim_record.issuer_id is not 32 bytes (${issuerRaw instanceof Uint8Array ? issuerRaw.length : typeof issuerRaw})`,
    );
  }
  return {
    claims: u32('claims'),
    expiresAt: u32('expires_at'),
    issuerId: new Uint8Array(issuerRaw),
    issuedAt: u32('issued_at'),
    revocationEpoch: u32('revocation_epoch'),
    revocationIndex: u32('revocation_index'),
  };
}

/**
 * Read the subject's whole {@link ClaimRecord}, with `revocationEpoch` as the load-bearing field.
 *
 * The whole record and not just the epoch, because a caller that has paid for the simulation needs
 * `claims` (is this a reinstatement or a renewal?), `expiresAt` (would my new expiry be refused as
 * status-list entry is this?) from the same read. Doing four reads for four fields would also mean
 * four chances of the epoch moving between them.
 */
export async function readSubjectChainState(
  sim: GateSimulator,
  subject: string,
): Promise<SubjectChainState> {
  // Validate the address BEFORE spending an RPC call, and before a malformed string can reach the
  // fake in a test and look like a chain problem.
  Address.fromString(subject);
  let raw: unknown;
  try {
    raw = await sim.simulateClaimRecord(subject);
  } catch (err) {
    const code = decodeContractErrorCode(err);
    if (code === KYC_GATE_ERRORS.NoClaimRecord) {
      // The ONE case that genuinely means epoch 0: nobody has ever attested OR revoked this subject.
      return { subject, revocationEpoch: 0, record: null, revoked: false };
    }
    if (code !== undefined) {
      // A DIFFERENT contract error. Named, so the operator sees which one, and still fatal —
      // `claim_record` has exactly one documented failure and this is not it.
      throw new EpochReadError(
        subject,
        new KycGateContractError(code, `claim_record(${subject})`, err).message,
        err,
      );
    }
    // Not a contract error at all: transport, timeout, DNS, a 502, a JSON parse failure, an
    // ambiguous diagnostic bundle naming two codes. None of these is evidence of anything.
    throw new EpochReadError(subject, String((err as Error)?.message ?? err), err);
  }
  let record: ClaimRecord;
  try {
    record = decodeClaimRecord(raw);
  } catch (err) {
    // A successful call whose payload we could not read is NOT epoch 0 either. This is the shape a
    // contract-id typo takes when the wrong contract happens to have a `claim_record` symbol.
    throw new EpochReadError(subject, String((err as Error)?.message ?? err), err);
  }
  return {
    subject,
    revocationEpoch: record.revocationEpoch,
    record,
    revoked: record.claims === 0,
  };
}

/** Convenience for callers that genuinely only want the number. Same discrimination, same failures. */
export async function readRevocationEpoch(sim: GateSimulator, subject: string): Promise<number> {
  return (await readSubjectChainState(sim, subject)).revocationEpoch;
}

/** What {@link SorobanGateSimulator} needs. */
export interface SorobanGateSimulatorConfig {
  /** Soroban RPC endpoint, e.g. `https://soroban-testnet.stellar.org`. */
  rpcUrl: string;
  networkPassphrase: string;
  /** The `kyc-gate` contract id. */
  gateContractId: string;
  /**
   * Source account for the read-only simulation. It DOES NOT NEED TO EXIST OR BE FUNDED, and that
   * was verified against live testnet rather than assumed: simulating `claim_record` with the source
   * `GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF` and sequence `0` returns the same
   * `HostError: Error(Contract, #3)` as simulating it with the funded deployer account.
   *
   * That matters for a gateway: it means the epoch read costs ONE RPC round trip, not two, and needs
   * because it is about to SUBMIT with that account anyway.
   */
  sourceAccountId?: string;
  /** Simulation fee, in stroops. Never charged — nothing is submitted. */
  fee?: string;
  /** Overall timeout for the RPC call, ms. A signing path that can hang has no bound at all. */
  timeoutMs?: number;
  /**
   * Permit a plain-`http://` RPC endpoint. Default `false`.
   *
   * The SDK refuses one outright otherwise — `new rpc.Server('http://…')` throws "Cannot connect to
   * insecure Soroban RPC server if `allowHttp` isn't set" at CONSTRUCTION, before any request. This
   * option exists because a local `stellar quickstart` container serves plain http and a gateway
   * developer needs to point at one; it defaults to `false` because a PRODUCTION gateway sending
   * subject addresses to an RPC endpoint over cleartext is leaking exactly the linkage the whole
   * product exists to avoid.
   */
  allowHttp?: boolean;
}

/**
 * All-zeros Ed25519 public key as a strkey. A valid, well-formed, certainly-unfunded address, used
 * only as a simulation source. Chosen over a random one so it is obvious in a request log that no
 * real account is involved.
 */
export const UNFUNDED_SIMULATION_SOURCE = 'GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF';

/**
 *
 * Simulation failures arrive as a RESOLVED response with an `error` string, not as a throw
 * (`rpc.Api.isSimulationError`), so this class converts them into a throw whose message carries the
 * `Error(Contract, #N)` text — which is the contract {@link GateSimulator} documents and the epoch
 * reader's discrimination depends on. Measured shape, from live testnet:
 *
 *     HostError: Error(Contract, #3)
 *
 *     Event log (newest first):
 *        0: [Diagnostic Event] contract:CDWW…, topics:[error, Error(Contract, #3)], …
 */
export class SorobanGateSimulator implements GateSimulator {
  readonly #server: rpc.Server;
  readonly #config: Required<Pick<SorobanGateSimulatorConfig, 'sourceAccountId' | 'fee' | 'timeoutMs'>> &
    SorobanGateSimulatorConfig;

  constructor(config: SorobanGateSimulatorConfig) {
    this.#config = {
      ...config,
      sourceAccountId: config.sourceAccountId ?? UNFUNDED_SIMULATION_SOURCE,
      fee: config.fee ?? '200000',
      timeoutMs: config.timeoutMs ?? 15_000,
    };
    this.#server = new rpc.Server(config.rpcUrl, { allowHttp: config.allowHttp ?? false });
  }

  async simulateClaimRecord(subject: string): Promise<unknown> {
    const tx = new TransactionBuilder(new Account(this.#config.sourceAccountId, '0'), {
      fee: this.#config.fee,
      networkPassphrase: this.#config.networkPassphrase,
    })
      .addOperation(
        new Contract(this.#config.gateContractId).call(
          'claim_record',
          Address.fromString(subject).toScVal(),
        ),
      )
      .setTimeout(30)
      .build();

    const sim = await withTimeout(
      this.#server.simulateTransaction(tx),
      this.#config.timeoutMs,
      `claim_record(${subject}) simulation`,
    );
    if (rpc.Api.isSimulationError(sim)) {
      // Deliberately preserves the whole diagnostic string: it is where the `Error(Contract, #N)`
      // lives, and truncating it is how a decoder stops working.
      throw new Error(`claim_record(${subject}) simulation failed: ${sim.error}`);
    }
    if (sim.result === undefined) {
      throw new Error(`claim_record(${subject}) simulation returned no result`);
    }
    return scValToNative(sim.result.retval);
  }

  /** Current ledger sequence — needed for `expires_at` and `not_valid_after`. */
  async latestLedger(): Promise<number> {
    const latest = await withTimeout(
      this.#server.getLatestLedger(),
      this.#config.timeoutMs,
      'getLatestLedger',
    );
    return latest.sequence;
  }
}

/** A hard deadline on a promise. `AbortController` would be better if the SDK took a signal; it does
 *  not, so this bounds the WAIT rather than the request. An unbounded wait on the signing path is an
 *  outage with no error message. */
async function withTimeout<T>(promise: Promise<T>, ms: number, label: string): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => reject(new Error(`${label} timed out after ${ms}ms`)), ms);
      }),
    ]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}
