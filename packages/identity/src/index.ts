/**
 * @stellaronramp/identity — off-chain BBS+ KYC credentials.
 *
 * Pure TypeScript. No chain access, no network calls, no PII storage. The gateway calls
 * `issue()`, the holder's SDK calls `prove()`/`derive()`, a relying party or the on-chain
 * verifier calls `verify()`/`checkPredicate()`.
 *
 * signed by the issuer, not a range proof over a date of birth, and that is a load-bearing
 * decision rather than a shortcut.
 */

export {
  CIPHERSUITE,
  CLAIM_INDEX,
  CLAIM_SPECS,
  CLAIM_SPEC_BY_INDEX,
  CREDENTIAL_HEADER,
  ISSUER_JURISDICTION_POLICY,
  MAX_SCHEMA_ATTRIBUTES,
  SCHEMA_ATTRIBUTE_COUNT,
  SCHEMA_VERSION,
  SUBJECT_BINDING_SALT_BYTES,
  SchemaError,
  assertNoPiiDisclosed,
  computeSubjectBinding,
  decodeDisclosed,
  encodeClaim,
  encodeClaims,
  normalizeIndexes,
  type ClaimIndex,
  type ClaimKind,
  type ClaimName,
  type ClaimSpec,
  type ClaimValue,
  type KycClaims,
} from './schema.js';

export {
  BINDING_DOMAIN,
  BindingError,
  NONCE_BYTES,
  PRESENTATION_HEADER_DOMAIN,
  PROOF_MAX_WINDOW,
  ReplayGuard,
  assertValidBinding,
  bindingDigest,
  bindingDigestHex,
  bindingsEqual,
  canonicalBindingBytes,
  presentationHeaderFor,
  randomNonce,
  type ProofBinding,
} from './binding.js';

export {
  FP_BYTES,
  G1_COMPRESSED_BYTES,
  G1_UNCOMPRESSED_BYTES,
  G2_COMPRESSED_BYTES,
  G2_UNCOMPRESSED_BYTES,
  PointError,
  SCALAR_BYTES,
  SIGNATURE_BYTES,
  compressG1,
  compressG2,
  decompressG1,
  decompressG2,
  expectedProofBytes,
  flattenSorobanProof,
  splitProof,
  splitSignature,
  toHex,
  undisclosedCountFromProofBytes,
  type SorobanProof,
  type SorobanSignature,
} from './points.js';

export {
  BBS_API_ID,
  BBS_GENERATOR_COUNT,
  GENERATORS_ROOT_ENCODING,
  GeneratorError,
  bbsGenerators,
  createGenerators,
  type BbsGenerators,
} from './generators.js';
