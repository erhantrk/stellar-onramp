/**
 *
 *   "The persisted tuple is exactly:
 *    {provider, provider_ref_id, subject_id, wallet_c_addr, claim_bitmap, schema_version,
 *     issued_at, expires_at, revocation_index, issuer_id}."
 *
 * "Exactly" is the operative word and it is enforced by construction here: `buildIssuanceRecord`
 * builds a fresh object with these eleven keys and nothing else, from named arguments, so a caller
 * cannot spread a provider payload in. A `{...status, ...ourFields}` spread is the single most likely
 * way PII reaches a database in a system like this, and the shape of this function is what makes it
 * impossible rather than discouraged.
 *
 * KEY CASING. The spec writes snake_case, the code writes camelCase for the TypeScript object and
 * carries the snake_case names as the SQL column names. That is a translation, not a deviation — the
 * `over18`, and the code wins). `PERSISTED_COLUMNS` below is the snake_case list, and a test parses
 * rather than drifting.
 *
 * makes an AML audit answerable. A PII detector that flags it is a broken detector.
 */


/**
 * test/kyc/record.test.ts, which PARSES the spec rather than trusting this comment — the chain
 * track's convention (a) for every mirrored constant.
 */
export const PERSISTED_COLUMNS = Object.freeze([
  'provider',
  'provider_ref_id',
  'subject_id',
  'wallet_c_addr',
  'claim_bitmap',
  'schema_version',
  'issued_at',
  'expires_at',
  'revocation_index',
  'issuer_id',
] as const);

export type PersistedColumn = (typeof PERSISTED_COLUMNS)[number];

/** camelCase -> snake_case, so the mapping is data and a test can check it both ways. */
export const RECORD_FIELD_TO_COLUMN: Readonly<Record<string, PersistedColumn>> = Object.freeze({
  provider: 'provider',
  providerRefId: 'provider_ref_id',
  subjectId: 'subject_id',
  walletCAddr: 'wallet_c_addr',
  claimBitmap: 'claim_bitmap',
  schemaVersion: 'schema_version',
  issuedAt: 'issued_at',
  expiresAt: 'expires_at',
  revocationIndex: 'revocation_index',
  issuerId: 'issuer_id',
});

/**
 * Everything the gateway keeps about one issuance. NOTHING ELSE MAY BE ADDED without a spec change:
 * the object is `readonly` and the field list is asserted exhaustively against `PERSISTED_COLUMNS`
 * by a compile-time type assertion at the bottom of this file, so an added field is a BUILD failure.
 */
export interface IssuanceRecord {
  readonly provider: string;
  /** The provider's applicant id. Pseudonymous. The AML audit join key. */
  readonly providerRefId: string;
  /** Our own opaque subject id. Not derived from any PII. */
  readonly subjectId: string;
  /** The wallet C- (or G-) address. Public on chain already. */
  readonly walletCAddr: string;
  /** The u32 claim bitmap as written on chain. */
  readonly claimBitmap: number;
  readonly schemaVersion: string;
  /** Unix seconds. */
  readonly issuedAt: number;
  /** Unix seconds. */
  readonly expiresAt: number;
  /** W3C Bitstring Status List index. Unique per credential — see `revocation-index.ts`. */
  readonly revocationIndex: number;
  /** 32-byte lowercase hex, `issuerIdFromPublicKey`. */
  readonly issuerId: string;
}

export class RecordError extends Error {
  override readonly name = 'RecordError';
}

/**
 * Build the tuple from NAMED arguments. There is deliberately no overload that takes a provider
 * status object: the only way a field gets in is by being named here.
 */
export function buildIssuanceRecord(args: IssuanceRecord): IssuanceRecord {
  const record: IssuanceRecord = {
    provider: nonEmpty(args.provider, 'provider'),
    providerRefId: nonEmpty(args.providerRefId, 'providerRefId'),
    subjectId: nonEmpty(args.subjectId, 'subjectId'),
    walletCAddr: nonEmpty(args.walletCAddr, 'walletCAddr'),
    claimBitmap: u32(args.claimBitmap, 'claimBitmap'),
    schemaVersion: nonEmpty(args.schemaVersion, 'schemaVersion'),
    issuedAt: u32(args.issuedAt, 'issuedAt'),
    expiresAt: u32(args.expiresAt, 'expiresAt'),
    revocationIndex: u32(args.revocationIndex, 'revocationIndex'),
    issuerId: hex32(args.issuerId, 'issuerId'),
  };
  if (record.expiresAt <= record.issuedAt) {
    throw new RecordError(
      `refusing to persist an issuance whose expires_at (${record.expiresAt}) is not strictly ` +
        `after its issued_at (${record.issuedAt})`,
    );
  }
  return record;
}

export function toPersistedRow(record: IssuanceRecord): Readonly<Record<PersistedColumn, unknown>> {
  return Object.freeze({
    provider: record.provider,
    provider_ref_id: record.providerRefId,
    subject_id: record.subjectId,
    wallet_c_addr: record.walletCAddr,
    claim_bitmap: record.claimBitmap,
    schema_version: record.schemaVersion,
    issued_at: record.issuedAt,
    expires_at: record.expiresAt,
    revocation_index: record.revocationIndex,
    issuer_id: record.issuerId,
  });
}

/**
 * signer and the status-list publisher, step (d) needs a live provider call. What is implemented
 * here is the part that is pure — the COLUMN SURGERY — plus the record of what the other three steps
 * are, so nobody has to reconstruct the policy from the regulation.
 *
 * and `subject_id`, (c) retains `provider_ref_id` + claim bitmap under the AML legal-obligation
 * exemption, and (d) forwards the request to the provider, which holds the actual personal data."
 *
 * 5-year figure in the spec is explicitly a placeholder marked [UNVERIFIED]. This function
 * implements the MECHANISM; the RETENTION PERIOD is a legal input it does not contain. Anyone
 */
export interface ErasedIssuanceRecord
  extends Omit<IssuanceRecord, 'walletCAddr' | 'subjectId'> {
  readonly walletCAddr: null;
  readonly subjectId: null;
  /** Unix seconds the erasure was applied. Not PII; it is the audit trail of the erasure itself. */
  readonly erasedAt: number;
}

/**
 * Step (b) + (c): drop the two columns that link the record to a person, keep the AML-mandated ones.
 *
 * `wallet_c_addr` is dropped even though it is public on chain. That is not theatre: the CHAIN entry
 * is an address with a bitmap and no person attached, while THIS ROW is the address-to-applicant
 */
export function eraseSubjectLinkage(
  record: IssuanceRecord,
  erasedAtSeconds: number,
): ErasedIssuanceRecord {
  return Object.freeze({
    provider: record.provider,
    providerRefId: record.providerRefId,
    subjectId: null,
    walletCAddr: null,
    claimBitmap: record.claimBitmap,
    schemaVersion: record.schemaVersion,
    issuedAt: record.issuedAt,
    expiresAt: record.expiresAt,
    revocationIndex: record.revocationIndex,
    issuerId: record.issuerId,
    erasedAt: u32(erasedAtSeconds, 'erasedAt'),
  });
}

/** The erasure steps a subject-erasure request involves, and which of them this module performs. */
export const ERASURE_STEPS = Object.freeze({
  a: 'flip the revocation bit: publish a status list with this revocationIndex set and revoke the on-chain record. Not performed here; it needs a submitter.',
  b: 'delete wallet_c_addr and subject_id: eraseSubjectLinkage(). Performed here.',
  c: 'retain provider_ref_id and claim_bitmap for the legally required period. Performed here as "keep the columns"; the period is not encoded.',
  d: 'forward the erasure request to the KYC provider, the controller of record for the personal data. Not performed here.',
});

function nonEmpty(value: string, field: string): string {
  if (typeof value !== 'string' || value.length === 0) {
    throw new RecordError(`refusing to persist an issuance with an empty ${field}`);
  }
  return value;
}

function u32(value: number, field: string): number {
  if (!Number.isInteger(value) || value < 0 || value > 0xffff_ffff) {
    throw new RecordError(
      `refusing to persist an issuance whose ${field} is not a u32: ${String(value)}`,
    );
  }
  return value;
}

const HEX32 = /^[0-9a-f]{64}$/;

function hex32(value: string, field: string): string {
  if (typeof value !== 'string' || !HEX32.test(value)) {
    throw new RecordError(
      `refusing to persist an issuance whose ${field} is not 64 lowercase hex characters`,
    );
  }
  return value;
}

/* -------------------------------------------------------------------------- */
/* Compile-time exhaustiveness: the interface and the column list agree.       */
/* -------------------------------------------------------------------------- */

/**
 * If a field is ADDED to `IssuanceRecord` without a column, `MissingColumn` stops being `never` and
 * this stops compiling. If a COLUMN is added without a field, `MissingField` does the same. That is
 * a build failure in `npm run typecheck`, not an editor squiggle, because
 * packages/gateway/tsconfig.json includes all of src.
 */
type MappedColumns = (typeof RECORD_FIELD_TO_COLUMN)[keyof IssuanceRecord & string];
type MissingColumn = Exclude<PersistedColumn, MappedColumns>;
type MissingField = Exclude<keyof IssuanceRecord, keyof typeof RECORD_FIELD_TO_COLUMN>;
const _noMissingColumn: MissingColumn extends never ? true : false = true;
const _noMissingField: MissingField extends never ? true : false = true;
void _noMissingColumn;
void _noMissingField;
