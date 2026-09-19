/**
 * Issuer preflight — is the issuer that signed this credential the one the CHAIN will verify
 * remains a regression harness; this is a COPY, not a move.
 *
 * `attest_bbs` does not take a public key. It reads `DataKey::Registry`, calls
 * `kyc-registry.active_key(issuer_id)` and verifies against whatever comes back — so the issuer
 * must be registered, and this is the read that says so BEFORE 105M instructions are spent finding
 * out (the measured cost of one `attest_bbs` simulation-and-land cycle). Checked against the local
 * key rather than merely fetched: a registry holding a different key for this id would fail the
 * proof with a cryptographic error nobody could read backwards.
 */

import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { decompressG2 } from '@stellaronramp/identity';
import { decodeContractErrorCode } from '@stellaronramp/gateway';
import { Buffer } from 'node:buffer';

import type { AttestSubmitter } from './submit.js';
import { contractCall } from './submit.js';
import { bytesScVal } from './scval.js';

/**
 * `kyc-registry`'s IssuerNotFound. THE SAME NUMBER as kyc-gate's NoClaimRecord (#3) — the two
 * contracts have separate `#[contracterror]` enums that happen to collide at 3 — which is exactly
 * why this module does NOT use the gateway package's `KYC_GATE_ERRORS` names for registry reads:
 * `isKycGateError(err, 'NoClaimRecord')` would be numerically right and semantically a lie. The
 * NUMBER is decoded with the shared, contract-agnostic `decodeContractErrorCode`; the NAME is
 * local to the registry.
 */
const REGISTRY_ISSUER_NOT_FOUND = 3;

export class IssuerPreflightError extends Error {
  override readonly name = 'IssuerPreflightError';
  /**
   * True ONLY when kyc-registry answered IssuerNotFound (#3) — the one outcome `register_issuer`
   * fixes. Everything else is an RPC or configuration failure that registering would not touch.
   */
  readonly issuerNotFound: boolean;

  constructor(message: string, opts: { readonly issuerNotFound: boolean; readonly cause?: unknown }) {
    super(message);
    this.name = 'IssuerPreflightError';
    this.issuerNotFound = opts.issuerNotFound;
    if (opts.cause !== undefined) this.cause = opts.cause;
  }
}

/**
 * Assert that `kyc-registry.active_key(issuerId)` returns EXACTLY the uncompressed G2 form of
 * `issuerPublicKeyCompressed`, and return the on-chain key as hex.
 *
 * DISCRIMINATE, the way the epoch reader does. `active_key` answers contract error #3
 * (IssuerNotFound) and ONLY that means "not registered". Catching everything and reporting it as
 * a missing registry entry would diagnose a timed-out RPC or a wrong RPC URL as a setup problem
 * and hand the operator a `register_issuer` command that fixes nothing.
 *
 * @throws IssuerPreflightError with `issuerNotFound: true` for #3; `false` for every other
 *   refusal (including a key MISMATCH — a different failure with a different remedy).
 */
export async function assertIssuerActive(
  submitter: Pick<AttestSubmitter, 'simulateRead'>,
  registryContractId: string,
  issuerIdHex: string,
  issuerPublicKeyCompressed: Uint8Array,
): Promise<string> {
  let registryKeyHex: string;
  try {
    const v = await submitter.simulateRead(
      contractCall(registryContractId, 'active_key', bytesScVal(hexToBytes(issuerIdHex))),
      'active_key',
    );
    registryKeyHex = Buffer.from(v as Uint8Array).toString('hex');
  } catch (cause) {
    const code = decodeContractErrorCode(cause);
    if (code === REGISTRY_ISSUER_NOT_FOUND) {
      throw new IssuerPreflightError(
        `issuer ${issuerIdHex.slice(0, 16)}… is not active on kyc-registry ${registryContractId} ` +
          '(IssuerNotFound, #3), so attest_bbs would answer UntrustedIssuer (#7). Register it ' +
          'as the registry admin: register_issuer --issuer_id <hex> --pk_g2 <192-byte ' +
          'uncompressed G2 hex> --valid_until 0.',
        { issuerNotFound: true, cause },
      );
    }
    throw new IssuerPreflightError(
      `could not read active_key from kyc-registry ${registryContractId}, and this was NOT ` +
        'IssuerNotFound (#3) — it is an RPC or configuration failure and registering an issuer ' +
        `will not fix it. Underlying cause: ${String((cause as Error)?.message ?? cause)}`,
      { issuerNotFound: false, cause },
    );
  }
  const expectedHex = bytesToHex(decompressG2(issuerPublicKeyCompressed));
  if (registryKeyHex !== expectedHex) {
    throw new IssuerPreflightError(
      'kyc-registry holds a DIFFERENT key for this issuer id — the proof would fail the pairing ' +
        'check with an error that says nothing about why. Stop here instead.',
      { issuerNotFound: false },
    );
  }
  return registryKeyHex;
}

/**
 * Walk `issuer_ids()` for a SECOND usable issuer — the substitute the negative tests need to reach
 * the issuer cross-check: an id the registry has never heard of is refused by the registry lookup
 * (#7 UntrustedIssuer) BEFORE the cross-check runs, so it proves nothing about the disclosed
 * messages. A substitute's stored key is checked for a clear flag byte too, because a set one is
 * refused (#6) by the cheap pubkey check that also runs before the cross-check — the right answer
 * for the wrong reason (lib.rs:1148-1173).
 *
 * Returns `null` when the registry holds no second usable issuer; callers then skip the #6 half
 * of the cross-check and SAY SO rather than claiming coverage they do not have.
 *
 * FAIL-CLOSED on transport: ONLY a contract-level #3 refusal means "not usable". An RPC or
 * network failure is rethrown — silently treating it as "no substitute" would quietly downgrade
 * the failure to its weaker #7-only form.
 */
export async function findSubstituteIssuer(
  submitter: Pick<AttestSubmitter, 'simulateRead'>,
  registryContractId: string,
  excludeIssuerIdHex: string,
): Promise<string | null> {
  const registryIds = (await submitter.simulateRead(
    contractCall(registryContractId, 'issuer_ids'),
    'issuer_ids',
  )) as Uint8Array[];
  for (const id of registryIds) {
    const candidate = Buffer.from(id).toString('hex');
    if (candidate === excludeIssuerIdHex) continue;
    // `issuer_ids()` is an append-only INVENTORY, not a list of usable issuers. `revoke_issuer`
    // sets the revoked flag and leaves the id in the list, after which `active_key` fails with
    // IssuerNotFound (kyc-registry/src/lib.rs:113-127 — revoked and expired both report #3, so
    // the caller cannot tell a retired issuer from one that was never there). Walk past those.
    // Concretely: 0101…0101 sat trusted on the testnet registry with an unusable key until it was
    // revoked, and this loop is what steps over its tombstone.
    let key: Uint8Array;
    try {
      key = (await submitter.simulateRead(
        contractCall(registryContractId, 'active_key', bytesScVal(hexToBytes(candidate))),
        'active_key (substitute)',
      )) as Uint8Array;
    } catch (cause) {
      const code = decodeContractErrorCode(cause);
      if (code === undefined || code !== REGISTRY_ISSUER_NOT_FOUND) throw cause;
      continue;
    }
    if ((Number(key[0]) & 0xe0) === 0) {
      return candidate;
    }
  }
  return null;
}
