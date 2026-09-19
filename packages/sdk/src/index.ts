/**
 * @stellaronramp/sdk — the HOLDER-side library: passkey smart-wallet → credential custody →
 *
 * WHAT IS HERE
 *
 *   config.ts          loadSdkConfig — deployments.json in, passive config out; fails closed
 *   wallet/            create/connect the passkey smart wallet; softwareP256WebAuthn (TEST/DEV)
 *   store.ts           CredentialStore: credential + subject-binding salt custody
 *   expiry.ts          ledgerExpiryFor / recordExpiresAtFor — the clamp identity deliberately omits
 *   attest/            the demo.ts step-8 wire machinery, promoted verbatim with its docblocks:
 *                        symbol.ts      ScMap symbol byte-ordering comparator
 *                        proof-scval.ts BbsProof scvMap builder (the 39-line measured block)
 *                        args.ts        the twelve attest_bbs arguments in wire order
 *                        grants.ts      claims-bitmap derivation mirroring lib.rs:1195-1227
 *                        submit.ts      submit/simulateRead/simulateError + landed-cost decode
 *                        registry.ts    issuer preflight vs kyc-registry.active_key (#3-only)
 *   gateway-client.ts  typed client for the gateway's REAL routes only
 *   session-signer.ts  FAIL-CLOSED SEAM — blocked upstream at Channels (error 7002, CAP-71)
 *
 *   createPasskeyWallet(...)            → C-address
 *   issue() + computeSubjectBinding(..) → credential bound to that C-address
 *   prove(credential, gateOnrampPredicate(), binding) with ledgerExpiryFor(server)
 *   attestBbsArgs({...})                → twelve wire arguments
 *   new AttestSubmitter({...}).submit(contractCall(gateId, 'attest_bbs', ...args))
 *
 * The holder NEVER signs for the attestation itself: `attest_bbs` binds its subject
 * cryptographically via the derived presentation header (lib.rs:1061 has no
 * subject.require_auth()), so the submission is funded by any ordinary source account.
 */

export {
  SdkConfigError,
  loadSdkConfig,
  type LoadSdkConfigOptions,
  type SdkConfig,
} from './config.js';

export {
  PASSKEY_WALLET_WASM_HASH,
  WalletError,
  relayerSubmitter,
  softwareP256WebAuthn,
  SoftwareAuthenticatorError,
  createPasskeyWallet,
  connectPasskeyWallet,
  type ConnectPasskeyWalletOptions,
  type CreatedWallet,
  type PasskeyWalletConfig,
  type SoftwareP256Authenticator,
  type SoftwareP256Options,
  type WalletDeploySubmitter,
} from './wallet/index.js';

export {
  StoreError,
  InMemoryCredentialStore,
  type CredentialStore,
  type StoredCredential,
} from './store.js';

export {
  DEFAULT_EXPIRY_MARGIN_LEDGERS,
  ExpiryError,
  LatestLedgerSource,
  ledgerExpiryFor,
  recordExpiresAtFor,
} from './expiry.js';

export {
  AttestError,
  SubmissionError,
} from './attest/errors.js';

export { compareSorobanSymbol, SYMBOL_CHARS } from './attest/symbol.js';
export { bbsProofScVal, BBS_PROOF_FIELD_ORDER } from './attest/proof-scval.js';
export { attestBbsArgs, type AttestBbsArgsInput } from './attest/args.js';
export { deriveGrantedClaims, ATTEST_GRANTS } from './attest/grants.js';
export {
  AttestSubmitter,
  contractCall,
  type LandedTx,
  type AttestSubmitterConfig,
  type SubmitOptions,
} from './attest/submit.js';
export {
  IssuerPreflightError,
  assertIssuerActive,
  findSubstituteIssuer,
} from './attest/registry.js';
export { addrScVal, bytesScVal, u32 } from './attest/scval.js';

export {
  GatewayClient,
  GatewayClientError,
  GatewayNotFoundError,
  GatewayNotImplementedError,
  GatewaySessionNotApprovedError,
  GatewayUnauthorizedError,
  GatewayForbiddenError,
  GatewayUnexpectedStatusError,
  GatewayUnavailableError,
  type GatewayClientConfig,
  type IssuedCredentialResponse,
  type IssueCredentialInput,
  type IssuerDocument,
  type SchemaDocument,
} from './gateway-client.js';
