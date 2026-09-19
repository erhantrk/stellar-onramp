/**
 * @stellaronramp/gateway — the issuer side: claim derivation, BBS+ credential issuance, the
 * status list, session tokens, and the reads the issuer makes against `kyc-gate`.
 */

export {
  CLAIM_JURISDICTION_OK,
  CLAIM_NOT_SANCTIONED,
  CLAIM_OVER_18,
  CLAIM_OVER_21,
  CLAIM_TTL_EXTEND_TO,
  LEDGERS_PER_DAY,
  LEDGER_SECONDS,
  MAX_EXPIRY_HORIZON,
  NONCE_MAX_TTL,
} from './chain/constants.js';
export {
  KYC_GATE_ERRORS,
  KycGateContractError,
  RETRIABLE_ERROR_CODES,
  decodeContractErrorCode,
  isKycGateError,
  isRetriableContractError,
  kycGateErrorName,
  type KycGateErrorCode,
  type KycGateErrorName,
} from './chain/errors.js';
export {
  EpochReadError,
  SorobanGateSimulator,
  UNFUNDED_SIMULATION_SOURCE,
  decodeClaimRecord,
  readRevocationEpoch,
  readSubjectChainState,
  type ClaimRecord,
  type GateSimulator,
  type LedgerClock,
  type SorobanGateSimulatorConfig,
  type SubjectChainState,
} from './chain/epoch.js';

export {
  AGE_THRESHOLDS,
  AgeError,
  ageAtUtc,
  deriveAgeClaims,
  parseCalendarDate,
  type CalendarDate,
} from './kyc/age.js';
export {
  BOOLEAN_CLAIM_NAMES,
  CLAIMS_WITHOUT_CHAIN_BITS,
  CLAIM_BIT_BY_NAME,
  ClaimDerivationError,
  claimBitmap,
  deriveClaimSet,
  jurisdictionAllowed,
  type BooleanClaimName,
} from './kyc/claims.js';
export {
  KycProviderError,
  REVIEW_ANSWERS,
  type ClaimSet,
  type KycProvider,
  type KycStatus,
  type ReviewAnswer,
} from './kyc/provider.js';
export {
  PII_ENCODINGS,
  PiiLeakError,
  assertNoPii,
  auditBytes,
  detectorControl,
  findEncodings,
  type PiiEncoding,
  type PiiSecret,
} from './kyc/pii.js';
export {
  ERASURE_STEPS,
  PERSISTED_COLUMNS,
  RECORD_FIELD_TO_COLUMN,
  RecordError,
  buildIssuanceRecord,
  eraseSubjectLinkage,
  toPersistedRow,
  type ErasedIssuanceRecord,
  type IssuanceRecord,
  type PersistedColumn,
} from './kyc/record.js';
export {
  InMemoryRevocationIndexAllocator,
  MAX_REVOCATION_INDEX,
  MINIMUM_LIST_CAPACITY,
  RevocationIndexError,
  assertUsableRevocationIndex,
  type RevocationIndexAllocator,
} from './kyc/revocation-index.js';
export {
  IssuanceError,
  freshSubjectBindingSalt,
  issueKycCredential,
  type IssueCredentialRequest,
  type IssuedCredential,
} from './kyc/issue.js';

export {
  BITSTRING_STATUS_LIST_CREDENTIAL_TYPE,
  BITSTRING_STATUS_LIST_TYPE,
  STATUS_LIST_CRYPTOSUITE,
  STATUS_LIST_DOMAIN,
  StatusCredentialError,
  VC_V2_CONTEXT,
  canonicalJson,
  decodeProofValue,
  encodeProofValue,
  parseXsdDateTime,
  signStatusListCredential,
  statusListSigningInput,
  toBitstringStatusList,
  toXsdDateTime,
  verifyStatusListCredential,
  type StatusListCredentialDocument,
  type StatusListProof,
} from './status/credential.js';
export {
  DEFAULT_STATUS_LIST_VALIDITY_SECONDS,
  assertHttpsUrl,
  publishStatusList,
  type PublishStatusListRequest,
} from './status/publisher.js';
export {
  DEFAULT_STATUS_LIST_CACHE_TTL_SECONDS,
  DEFAULT_STATUS_LIST_MAX_AGE_SECONDS,
  DEFAULT_STATUS_LIST_TIMEOUT_MS,
  FetchStatusListHttp,
  HardenedStatusListResolver,
  MAX_STATUS_LIST_REDIRECTS,
  StatusListResolutionError,
  type HardenedStatusListResolverConfig,
  type PinnedStatusListIssuer,
  type StatusListHttp,
  type StatusListHttpResponse,
  type StatusListProvenance,
  type StatusListResolutionReason,
} from './status/resolver.js';

export {
  EDDSA,
  ES256,
  JwsError,
  REPLAY_UNCHECKED_NOTE,
  ed25519PublicKeyFromRaw,
  es256PublicKeyFromJwk,
  generateEs256KeyPair,
  signJws,
  verifyJws,
  type JtiReplayStore,
  type JwsClaimsInput,
  type JwsRejectionReason,
  type VerifiedJws,
  type VerifyJwsOptions,
} from './auth/jws.js';
