/**
 * The twelve positional arguments of `kyc-gate.attest_bbs`, in wire order.
 * this is a COPY, not a move.
 */

import { hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { CREDENTIAL_HEADER, splitProof } from '@stellaronramp/identity';
import type { Proof } from '@stellaronramp/identity';
import { xdr } from '@stellar/stellar-sdk';

import { AttestError } from './errors.js';
import { bbsProofScVal } from './proof-scval.js';
import { addrScVal, bytesScVal, u32 } from './scval.js';

const HEX_32_RE = /^[0-9a-f]{64}$/;

export interface AttestBbsArgsInput {
  /** The attestation subject — the holder's wallet address (`C…` for a passkey wallet; the
   *  contract's subject binding accepts both G- and C-strkeys via identity's own regexes). */
  readonly subject: string;
  /** 32-byte lowercase-hex issuer id, as `issuerIdFromPublicKey` produces it. */
  readonly issuerId: string;
  /**
   * The claims bitmap — DERIVED via `deriveGrantedClaims(proof)`, never chosen. The contract
   * re-derives the grantable set and refuses any bit outside it with `InvalidProof` (#6).
   */
  readonly claimsBitmap: number;
  /** Record lifetime in LEDGER-SEQUENCE units — the contract compares it against
   *  `env.ledger().sequence()` (`lib.rs:1081-1087`: below → `Expired`, lead > horizon →
   *  `ExpiryTooFar`). Build it with `recordExpiresAtFor`. Relayer-chosen on this contract
   *  residual; do not re-open. */
  readonly expiresAt: number;
  /** A fresh subject is at 0. Read it back via the gateway package's epoch reader if unsure —
   *  never assume 0 for an address that may already hold a record. */
  readonly revocationEpoch: number;
  /** Status-list slot this credential discloses at index 2; cross-checked against the proof. */
  readonly revocationIndex: number;
  /** The derived proof (carries its bytes plus the disclosed indexes/messages). */
  readonly proof: Proof;
  /** The binding's 32-byte nonce, lowercase hex — the SAME nonce inside the proof's challenge. */
  readonly nonceHex: string;
  /** Ledger the proof dies at; clamp through `ledgerExpiryFor` before calling. */
  readonly ledgerExpiry: number;
}

/**
 * Build the twelve arguments of `attest_bbs`, identical in every position to
 *
 * Position 10 (`header`) is the **CREDENTIAL header** (`identity::CREDENTIAL_HEADER`, the BBS+
 * domain over which the credential itself was signed), **NOT the presentation header**: the
 * presentation header is derived by the CONTRACT from {nonce, subject, its own address,
 * network_id, ledger_expiry} and is not an argument at all. Passing the wrong header here fails
 * the pairing check on chain
 * with an opaque `InvalidProof` (#6).
 */
export function attestBbsArgs(input: AttestBbsArgsInput): xdr.ScVal[] {
  if (!HEX_32_RE.test(input.issuerId)) {
    throw new AttestError(`issuerId must be 32 lowercase hex bytes, got "${input.issuerId}"`);
  }
  if (!HEX_32_RE.test(input.nonceHex)) {
    throw new AttestError(`nonceHex must be 32 lowercase hex bytes, got "${input.nonceHex}"`);
  }
  if (!Number.isInteger(input.claimsBitmap) || input.claimsBitmap < 0 || input.claimsBitmap > 0xffff_ffff) {
    throw new AttestError(`claimsBitmap ${String(input.claimsBitmap)} is not a u32`);
  }
  if (!Number.isInteger(input.revocationIndex) || input.revocationIndex < 0 || input.revocationIndex > 0xffff_ffff) {
    throw new AttestError(`revocationIndex ${String(input.revocationIndex)} is not a u32`);
  }
  if (!Number.isInteger(input.expiresAt) || input.expiresAt <= 0 || input.expiresAt > 0xffff_ffff) {
    throw new AttestError(`expiresAt ${String(input.expiresAt)} is not a positive u32 ledger sequence`);
  }
  if (!Number.isInteger(input.ledgerExpiry) || input.ledgerExpiry <= 0 || input.ledgerExpiry > 0xffff_ffff) {
    throw new AttestError(`ledgerExpiry ${String(input.ledgerExpiry)} is not a positive u32 ledger`);
  }

  return [
    addrScVal(input.subject), // 1  subject(Address)
    bytesScVal(hexToBytes(input.issuerId)), // 2  issuer_id(bytes32)
    u32(input.claimsBitmap), // 3  claims(u32)
    u32(input.expiresAt), // 4  expires_at(u32)
    u32(input.revocationEpoch), // 5  revocation_epoch(u32)
    u32(input.revocationIndex), // 6  revocation_index(u32)
    bbsProofScVal(splitProof(input.proof.proof)), // 7  proof(BbsProof map)
    xdr.ScVal.scvVec([...input.proof.disclosedIndexes].map((i) => u32(i))), // 8 disclosed_indexes(vec<u32>)
    xdr.ScVal.scvVec(
      [...input.proof.disclosedMessages].map((m) => bytesScVal(utf8ToBytes(m))),
    ), // 9  disclosed_messages(vec<bytes>)
    bytesScVal(utf8ToBytes(CREDENTIAL_HEADER)), // 10 the CREDENTIAL header, NOT the presentation one
    bytesScVal(hexToBytes(input.nonceHex)), // 11 nonce(bytes32)
    u32(input.ledgerExpiry), // 12 ledger_expiry(u32)
  ];
}
