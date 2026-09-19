/**
 * expected-refusal simulation.
 *
 * `simulateError` (:1172-1183) — with the demo's process-global `costs[]` array replaced by a
 *
 * WHY A CLASS: the demo closed over module globals (`server`, `NETWORK_PASSPHRASE`,
 * `deployerKp`). A library cannot do that, so the three closures become methods on
 * {@link AttestSubmitter}, constructed with one frozen config object — the repo's standard config
 * threading (`apps/gateway-http/src/types.ts::AppConfig` is the reference). The submitter keypair
 * is the FUNDED source that pays for the attestation: `attest_bbs` does NOT require the subject's
 * signature (the subject is bound cryptographically via the derived presentation header —
 * `contracts/kyc-gate/src/lib.rs:1061` has no `subject.require_auth()`), so the wallet never
 * signs and never funds. On testnet that source is the repo's `stellaronramp-dev` alias key.
 */

import { Contract, TransactionBuilder, rpc, scValToNative } from '@stellar/stellar-sdk';
import type { Keypair, Transaction, xdr } from '@stellar/stellar-sdk';

import { SubmissionError } from './errors.js';

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

/**
 * What a LANDED transaction actually consumed, decoded from the envelope the network kept.
 *
 * Simulation numbers are estimates and they are the ones everybody quotes; these are not. The
 * resources come off `envelopeXdr.v1().tx().ext().sorobanData()` — note `readBytes` is
 * `diskReadBytes` in this SDK — and `feeCharged` off the transaction RESULT, which is the fee
 * after the refundable portion was returned. `resourceFeeDeclaredStroops` is what the submitter
 * committed to pay (`prepareTransaction` pads it); it is recorded so the two are never confused.
 */
export interface LandedTx {
  readonly call: string;
  readonly hash: string;
  readonly instructions: number;
  readonly diskReadBytes: number;
  readonly writeBytes: number;
  /** The DURABILITIES of the read-write footprint, sorted and joined — `persistent+temporary`
   *  Recorded because a byte count alone cannot tell you whether two calls wrote the same shape
   *  or coincidentally the same size. */
  readonly writeFootprint: string;
  readonly resourceFeeDeclaredStroops: number;
  readonly feeChargedStroops: number;
}

export interface AttestSubmitterConfig {
  /** A live Soroban RPC client (`new rpc.Server(url, { allowHttp })`). */
  readonly server: rpc.Server;
  readonly networkPassphrase: string;
  /** The FUNDED keypair that signs and pays. Not the wallet — see module docblock. */
  readonly submitter: Keypair;
  /** Fee for the SUBMIT path in stroops. The demo used 2,000,000; simulation overhead is padded
   *  by `prepareTransaction` anyway, so this is headroom, not a price. */
  readonly submitFeeStroops?: string;
  /** Read path fee (simulations are free; the fee only shapes the tx). Demo used 200,000. */
  readonly readFeeStroops?: string;
  readonly timeoutSeconds?: number;
  readonly pollAttempts?: number;
  readonly pollIntervalMs?: number;
}

export interface SubmitOptions {
  /** Overrides the config-level fee for one call. */
  readonly feeStroops?: string;
}

export class AttestSubmitter {
  readonly #server: rpc.Server;
  readonly #networkPassphrase: string;
  readonly #submitter: Keypair;
  readonly #submitFeeStroops: string;
  readonly #readFeeStroops: string;
  readonly #timeoutSeconds: number;
  readonly #pollAttempts: number;
  readonly #pollIntervalMs: number;

  constructor(config: AttestSubmitterConfig) {
    this.#server = config.server;
    this.#networkPassphrase = config.networkPassphrase;
    this.#submitter = config.submitter;
    this.#submitFeeStroops = config.submitFeeStroops ?? '2000000';
    this.#readFeeStroops = config.readFeeStroops ?? '200000';
    this.#timeoutSeconds = config.timeoutSeconds ?? 60;
    this.#pollAttempts = config.pollAttempts ?? 40;
    this.#pollIntervalMs = config.pollIntervalMs ?? 1000;
  }

  /**
   * Submit and wait. `prepareTransaction` simulates first, which is not optional: post-Protocol-23
   * auto-restore of archived entries only happens when RPC simulation populates the restore
   *
   * Costs are read off the CONFIRMED envelope, and nowhere else — every number in the returned
   * `LandedTx` is what the network charged, not what a simulation guessed it might.
   */
  async submit(op: ReturnType<Contract['call']>, label: string, opts: SubmitOptions = {}): Promise<LandedTx> {
    const tx = await this.#build(op, opts.feeStroops ?? this.#submitFeeStroops, this.#timeoutSeconds);
    let prepared;
    try {
      prepared = await this.#server.prepareTransaction(tx);
    } catch (cause) {
      // Simulation failures surface HERE for submissions (the simulate happens inside prepare).
      // The error text carries the contract diagnostic; decode it with
      // `decodeContractErrorCode` rather than matching prose.
      throw new SubmissionError(`${label} failed pre-submit simulation: ${String((cause as Error)?.message ?? cause)}`, { cause });
    }
    prepared.sign(this.#submitter);
    let sent;
    try {
      sent = await this.#server.sendTransaction(prepared);
    } catch (cause) {
      throw new SubmissionError(`${label} rejected on submit: ${String((cause as Error)?.message ?? cause)}`, { cause });
    }
    if (sent.status === 'ERROR') { // rpc.Api.SendTransactionStatus is a string-literal union type
      throw new SubmissionError(`${label} rejected on submit: ${JSON.stringify(sent.errorResult)}`);
    }
    for (let i = 0; i < this.#pollAttempts; i++) {
      const got = await this.#server.getTransaction(sent.hash);
      if (got.status === rpc.Api.GetTransactionStatus.SUCCESS) {
        const soroban = got.envelopeXdr.v1().tx().ext().sorobanData();
        const res = soroban.resources();
        // A footprint entry need not be contract data (a TTL or instance key is not), so switch on
        // the key type before reaching for `durability()` — that call throws on the others.
        const writeFootprint = res
          .footprint()
          .readWrite()
          .map((k) =>
            k.switch().name === 'contractData' ? k.contractData().durability().name : k.switch().name,
          )
          .sort()
          .join('+');
        return {
          call: label,
          hash: sent.hash,
          instructions: res.instructions(),
          diskReadBytes: res.diskReadBytes(),
          writeBytes: res.writeBytes(),
          writeFootprint,
          resourceFeeDeclaredStroops: Number(soroban.resourceFee().toString()),
          feeChargedStroops: Number(got.resultXdr.feeCharged().toString()),
        };
      }
      if (got.status === rpc.Api.GetTransactionStatus.FAILED) {
        throw new SubmissionError(`${label} FAILED on chain: ${JSON.stringify(got.resultXdr?.toXDR('base64'))}`);
      }
      await sleep(this.#pollIntervalMs);
    }
    throw new SubmissionError(`${label} never confirmed`);
  }

  /** Read-only path. A dApp never pays for a `check()` — it simulates it. */
  async simulateRead(op: ReturnType<Contract['call']>, label: string): Promise<unknown> {
    const tx = await this.#build(op, this.#readFeeStroops, 30);
    const sim = await this.#server.simulateTransaction(tx);
    if (rpc.Api.isSimulationError(sim)) {
      throw new SubmissionError(`${label} simulation failed: ${sim.error}`);
    }
    if (sim.result === undefined) {
      throw new SubmissionError(`${label} simulation returned no result`);
    }
    return scValToNative(sim.result.retval);
  }

  /**
   * Simulate an invocation that is EXPECTED to be refused, and hand back the host's error string
   * (or `null` if it succeeded, which is the caller's assertion to make).
   *
   * Simulation, not submission, and not because it is cheaper: a submitted failure is only visible
   * as a base64 result XDR, whereas simulation returns the host diagnostic with the contract error
   * NUMBER in it. "Did not work" is not the claim a refusal test needs to make — "was refused with
   * #6, specifically" is. Decode the number with `decodeContractErrorCode` from
   * `@stellaronramp/gateway`; do not regex the string at call sites.
   */
  async simulateError(op: ReturnType<Contract['call']>): Promise<string | null> {
    const tx = await this.#build(op, this.#readFeeStroops, 30);
    const sim = await this.#server.simulateTransaction(tx);
    return rpc.Api.isSimulationError(sim) ? sim.error : null;
  }

  async #build(
    op: ReturnType<Contract['call']>,
    fee: string,
    timeoutSeconds: number,
  ): Promise<Transaction> {
    const account = await this.#server.getAccount(this.#submitter.publicKey());
    return new TransactionBuilder(account, {
      fee,
      networkPassphrase: this.#networkPassphrase,
    })
      .addOperation(op)
      .setTimeout(timeoutSeconds)
      .build();
  }
}

/**
 * Build an invocation against a deployed contract by id — the one-liner every call site needs
 * (`new Contract(id).call(method, ...args)`), exported so consumers do not import `Contract`
 * just for this.
 */
export function contractCall(
  contractId: string,
  method: string,
  ...args: xdr.ScVal[]
): ReturnType<Contract['call']> {
  return new Contract(contractId).call(method, ...args);
}
