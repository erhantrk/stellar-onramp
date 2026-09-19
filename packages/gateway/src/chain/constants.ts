/** Claim bits, as `kyc-gate` stores them. Frozen: never renumber, only append. */
export const CLAIM_OVER_18 = 1 << 0;
export const CLAIM_OVER_21 = 1 << 1;
export const CLAIM_NOT_SANCTIONED = 1 << 2;
export const CLAIM_JURISDICTION_OK = 1 << 3;

/** `kyc-gate` bumps a claim record's TTL to this many ledgers on every write. */
export const CLAIM_TTL_EXTEND_TO = 2_073_600;
/** The longest a consumed-nonce entry can live: the network's `max_entry_ttl - 1`. */
export const NONCE_MAX_TTL = 3_110_399;
/** The furthest ahead `attest_bbs` accepts an `expires_at`. */
export const MAX_EXPIRY_HORIZON = Math.min(CLAIM_TTL_EXTEND_TO, NONCE_MAX_TTL);

export const LEDGER_SECONDS = 5;
export const LEDGERS_PER_DAY = Math.floor((24 * 60 * 60) / LEDGER_SECONDS);
