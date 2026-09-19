/**
 * Frozen credential schema, v1.
 *
 * BBS+ selective disclosure has exactly one lever — `disclosedMessageIndexes`, a set of
 * WHOLE-message reveal/hide selectors. `deriveProof` has no `bounds`/`range`/`predicate`
 * parameter, and that is inherent to draft-irtf-cfrg-bbs-signatures-08, not a library gap.
 * So "prove age > 18 from a DOB" is not expressible. The composable alternative
 * (@docknetwork/crypto-wasm-ts LegoGroth16/Bulletproofs++) was rejected: it needs a second,
 * unmeasured on-chain verifier plus a per-circuit trusted setup, and ships 1.5 MiB of WASM.
 *
 * Therefore the ISSUER pre-derives the booleans at issuance time and signs each one as its own
 * BBS+ message. The credential contains NO raw DOB, NO name, NO document number, NO country.
 * It cannot leak PII because it does not carry any. That is the whole design.
 *
 * INDEX DISCIPLINE: these indices are FROZEN. Never renumber, never delete, never reorder —
 * an index is baked into every issued credential, every derived proof, and the on-chain
 * verifier's generator ordering. Adding an attribute means appending at the next free index
 */

import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, concatBytes, utf8ToBytes } from '@noble/hashes/utils.js';

/** Frozen message indices. Append-only. */
export const CLAIM_INDEX = {
  /** "1" — pinned so an old verifier cannot be tricked into reading a v2 credential. */
  schemaVersion: 0,
  /** 32-byte lowercase hex identifying the issuing gateway key. */
  issuerId: 1,
  /** Bitstring Status List position, for revocation lookups in `kyc-registry`. */
  revocationIndex: 2,
  /** Unix seconds. */
  issuedAt: 3,
  /** Unix seconds. Enforced by the holder, the verifier, and `ClaimRecord.expires_at`. */
  expiresAt: 4,
  /** sha256(wallet C-address ‖ salt), lowercase hex. Binds the credential to a wallet
   *  without putting the address itself in the clear inside the credential. */
  subjectBinding: 5,
  over18: 6,
  over21: 7,
  notSanctioned: 8,
  notPep: 9,
  /** Issuer asserts the holder's residence is inside ISSUER_JURISDICTION_POLICY. */
  jurisdictionOk: 10,
  livenessOk: 11,
} as const;

export type ClaimName = keyof typeof CLAIM_INDEX;
export type ClaimIndex = (typeof CLAIM_INDEX)[ClaimName];

export const SCHEMA_ATTRIBUTE_COUNT = 12;

/**
 * per-transaction budget; 40 busts both the "under 100 M" and "under 25 %" bounds.
 *
 * and by `points.ts` (`expectedProofBytes` / `undisclosedCountFromProofBytes` refuse U > 39).
 * Before that it was a documented number with a test that asserted `12 <= 39`, which is not the
 * same thing as a check.
 */
export const MAX_SCHEMA_ATTRIBUTES = 39;

// Load-time guard, in the same spirit as the domain-width guards in the gateway's constants.ts:
// a schema append that busts the on-chain cost budget must fail at import, not at the first
// attestation that runs out of instructions on chain. Unreachable today (12 <= 39) and that is
// the point — it is here for the v2 append that CLAIM_INDEX's docblock invites.
if (SCHEMA_ATTRIBUTE_COUNT > MAX_SCHEMA_ATTRIBUTES) {
  throw new Error(
    `the frozen schema declares ${SCHEMA_ATTRIBUTE_COUNT} attributes, over ` +
      `the schema's cap of ${MAX_SCHEMA_ATTRIBUTES}: on-chain verification would cost ` +
      `${41_980_626 + 1_471_918 * SCHEMA_ATTRIBUTE_COUNT} instructions, past the 100M bound.`,
  );
}

export const SCHEMA_VERSION = '1';

/** BBS+ ciphersuite. Fixed; the on-chain verifier hard-codes the same domain separators. */
export const CIPHERSUITE = 'BLS12-381-SHA-256';

/**
 * BBS+ `header` — constant per schema version, hashed into `calculate_domain` alongside the
 * generators and the message count. Making it a constant (rather than per-credential data)
 * lets the on-chain verifier recompute `domain` without receiving it as untrusted input.
 */
export const CREDENTIAL_HEADER = `stellaronramp/kyc-credential/v${SCHEMA_VERSION}`;

/** Value kinds, so canonical encoding is total and unambiguous. */
export type ClaimKind = 'string' | 'hex32' | 'uint' | 'bool';

export interface ClaimSpec {
  readonly name: ClaimName;
  readonly index: ClaimIndex;
  readonly kind: ClaimKind;
  /**
   * Whether this attribute is PII-bearing. Every v1 attribute is `false` — the schema is
   * PII-free by construction. The flag exists so a future append cannot slip PII in silently:
   * `assertNoPiiDisclosed` refuses to derive a proof that reveals a PII-bearing index.
   */
  readonly pii: boolean;
}

export const CLAIM_SPECS: readonly ClaimSpec[] = [
  { name: 'schemaVersion', index: CLAIM_INDEX.schemaVersion, kind: 'string', pii: false },
  { name: 'issuerId', index: CLAIM_INDEX.issuerId, kind: 'hex32', pii: false },
  { name: 'revocationIndex', index: CLAIM_INDEX.revocationIndex, kind: 'uint', pii: false },
  { name: 'issuedAt', index: CLAIM_INDEX.issuedAt, kind: 'uint', pii: false },
  { name: 'expiresAt', index: CLAIM_INDEX.expiresAt, kind: 'uint', pii: false },
  { name: 'subjectBinding', index: CLAIM_INDEX.subjectBinding, kind: 'hex32', pii: false },
  { name: 'over18', index: CLAIM_INDEX.over18, kind: 'bool', pii: false },
  { name: 'over21', index: CLAIM_INDEX.over21, kind: 'bool', pii: false },
  { name: 'notSanctioned', index: CLAIM_INDEX.notSanctioned, kind: 'bool', pii: false },
  { name: 'notPep', index: CLAIM_INDEX.notPep, kind: 'bool', pii: false },
  { name: 'jurisdictionOk', index: CLAIM_INDEX.jurisdictionOk, kind: 'bool', pii: false },
  { name: 'livenessOk', index: CLAIM_INDEX.livenessOk, kind: 'bool', pii: false },
] as const;

/** index -> spec, dense. */
export const CLAIM_SPEC_BY_INDEX: readonly ClaimSpec[] = (() => {
  const out = new Array<ClaimSpec>(SCHEMA_ATTRIBUTE_COUNT);
  for (const s of CLAIM_SPECS) out[s.index] = s;
  return out;
})();

export type ClaimValue = string | number | boolean;

/** The claim set an issuer signs. Every index must be present — BBS+ has no optional messages. */
export type KycClaims = {
  schemaVersion: string;
  issuerId: string;
  revocationIndex: number;
  issuedAt: number;
  expiresAt: number;
  subjectBinding: string;
  over18: boolean;
  over21: boolean;
  notSanctioned: boolean;
  notPep: boolean;
  jurisdictionOk: boolean;
  livenessOk: boolean;
};

/**
 * The issuer's published jurisdiction policy: the ISO-3166-1 alpha-2 set for which the gateway
 * attribute); it is a public issuer parameter. `countryAllowed()` uses it to decide whether a
 * relying party's allowlist is satisfiable by a `jurisdictionOk` disclosure — see predicates.ts.
 */
export const ISSUER_JURISDICTION_POLICY: readonly string[] = [
  'AT', 'BE', 'CH', 'CZ', 'DE', 'DK', 'EE', 'ES', 'FI', 'FR', 'GB', 'IE', 'IT',
  'LT', 'LU', 'LV', 'NL', 'NO', 'PL', 'PT', 'SE', 'SI', 'SK',
] as const;

const HEX32 = /^[0-9a-f]{64}$/;

export class SchemaError extends Error {
  override readonly name = 'SchemaError';
}

/**
 *
 * WHY THIS FUNCTION HAS TO EXIST: without it the attribute is decorative. A BBS+ proof attests
 * "some credential signed by this issuer says over18=true" — it says NOTHING about *whose*
 * credential it is. One KYC'd holder can otherwise derive an unlimited number of valid proofs,
 * each bound to a different wallet, and gate every one of them. `subject_binding` is the only
 * thing in the schema that pins a credential to a wallet, so the relying party must be able to
 * recompute it and `verifyDetailed` must be able to compare it (`expectedSubjectBinding`).
 *
 * The salt is held by the holder alongside the credential and is not itself a secret in any
 * cryptographic sense — it exists so that the same wallet address does not produce the same
 * commitment across issuers, which would make credentials cross-linkable.
 */
export const SUBJECT_BINDING_SALT_BYTES = 32;

export function computeSubjectBinding(walletAddress: string, salt: Uint8Array): string {
  if (typeof walletAddress !== 'string' || !/^[GC][A-Z2-7]{55}$/.test(walletAddress)) {
    throw new SchemaError('subject binding requires a Stellar C- or G-address');
  }
  if (!(salt instanceof Uint8Array) || salt.length !== SUBJECT_BINDING_SALT_BYTES) {
    throw new SchemaError(`subject binding salt must be ${SUBJECT_BINDING_SALT_BYTES} bytes`);
  }
  // Fixed-width inputs (56 ASCII chars ‖ 32 bytes) so no length prefix is needed to keep the
  // concatenation unambiguous.
  return bytesToHex(sha256(concatBytes(utf8ToBytes(walletAddress), salt)));
}

/**
 * Canonical message encoding: `name=value`, UTF-8.
 *
 * The attribute NAME is inside the signed bytes. That is deliberate: without it, two same-typed
 * attributes (e.g. over18 / over21) differ only by position, so a verifier that mixed up the
 * index order would still see a "valid" signature over semantically swapped claims. With the
 * name inside, a reorder produces messages that no longer match what the verifier expects at
 * that index and verification fails loudly.
 */
export function encodeClaim(name: ClaimName, value: ClaimValue): string {
  const spec = CLAIM_SPECS.find((s) => s.name === name);
  if (spec === undefined) throw new SchemaError(`unknown claim "${name}"`);
  return `${name}=${encodeValue(spec, value)}`;
}

function encodeValue(spec: ClaimSpec, value: ClaimValue): string {
  switch (spec.kind) {
    case 'bool':
      if (typeof value !== 'boolean') {
        throw new SchemaError(`claim "${spec.name}" must be boolean, got ${typeof value}`);
      }
      return value ? 'true' : 'false';
    case 'uint': {
      if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) {
        throw new SchemaError(`claim "${spec.name}" must be a non-negative safe integer`);
      }
      return String(value);
    }
    case 'hex32': {
      if (typeof value !== 'string' || !HEX32.test(value)) {
        throw new SchemaError(`claim "${spec.name}" must be 64 lowercase hex chars`);
      }
      return value;
    }
    case 'string': {
      if (typeof value !== 'string' || value.length === 0) {
        throw new SchemaError(`claim "${spec.name}" must be a non-empty string`);
      }
      // '=' would make the name/value split ambiguous for the on-chain re-encoder.
      if (value.includes('=')) {
        throw new SchemaError(`claim "${spec.name}" must not contain "="`);
      }
      return value;
    }
  }
}

/** Encode a full claim set into the ordered BBS+ message array (index i == CLAIM_INDEX). */
export function encodeClaims(claims: KycClaims): string[] {
  const messages = new Array<string>(SCHEMA_ATTRIBUTE_COUNT);
  for (const spec of CLAIM_SPECS) {
    const value = (claims as Record<string, ClaimValue | undefined>)[spec.name];
    if (value === undefined) {
      throw new SchemaError(`missing claim "${spec.name}" (index ${spec.index})`);
    }
    messages[spec.index] = encodeClaim(spec.name, value);
  }
  return messages;
}

/** Inverse of `encodeClaims` for a *partial* (disclosed) message set. */
export function decodeDisclosed(
  indexes: readonly number[],
  messages: readonly string[],
): Partial<Record<ClaimName, ClaimValue>> {
  if (indexes.length !== messages.length) {
    throw new SchemaError('disclosed index/message length mismatch');
  }
  const out: Partial<Record<ClaimName, ClaimValue>> = {};
  indexes.forEach((idx, i) => {
    const spec = CLAIM_SPEC_BY_INDEX[idx];
    const raw = messages[i];
    if (spec === undefined) throw new SchemaError(`index ${idx} is not in schema v${SCHEMA_VERSION}`);
    if (raw === undefined) throw new SchemaError(`missing disclosed message at position ${i}`);
    const sep = raw.indexOf('=');
    if (sep < 0) throw new SchemaError(`malformed disclosed message at position ${i}`);
    const name = raw.slice(0, sep);
    const value = raw.slice(sep + 1);
    // A message whose embedded name disagrees with its index is an index-substitution attempt.
    if (name !== spec.name) {
      throw new SchemaError(
        `disclosed message at index ${idx} names "${name}" but schema says "${spec.name}"`,
      );
    }
    out[spec.name] = decodeValue(spec, value);
  });
  return out;
}

function decodeValue(spec: ClaimSpec, value: string): ClaimValue {
  switch (spec.kind) {
    case 'bool':
      if (value !== 'true' && value !== 'false') {
        throw new SchemaError(`claim "${spec.name}" has non-canonical boolean "${value}"`);
      }
      return value === 'true';
    case 'uint': {
      if (!/^(0|[1-9][0-9]*)$/.test(value)) {
        throw new SchemaError(`claim "${spec.name}" has non-canonical uint "${value}"`);
      }
      const n = Number(value);
      if (!Number.isSafeInteger(n)) throw new SchemaError(`claim "${spec.name}" out of safe range`);
      return n;
    }
    case 'hex32':
      if (!HEX32.test(value)) throw new SchemaError(`claim "${spec.name}" is not 32-byte hex`);
      return value;
    case 'string':
      if (value.length === 0) throw new SchemaError(`claim "${spec.name}" is empty`);
      return value;
  }
}

/** Normalise + validate a disclosure index set: sorted ascending, unique, in range, PII-free. */
export function normalizeIndexes(indexes: readonly number[]): number[] {
  const seen = new Set<number>();
  for (const idx of indexes) {
    if (!Number.isInteger(idx) || idx < 0 || idx >= SCHEMA_ATTRIBUTE_COUNT) {
      throw new SchemaError(`disclosure index ${idx} out of range [0,${SCHEMA_ATTRIBUTE_COUNT})`);
    }
    if (seen.has(idx)) throw new SchemaError(`duplicate disclosure index ${idx}`);
    seen.add(idx);
  }
  const sorted = [...seen].sort((a, b) => a - b);
  assertNoPiiDisclosed(sorted);
  return sorted;
}

/** Guardrail for future schema appends; a no-op on v1, which has no PII-bearing attributes. */
export function assertNoPiiDisclosed(indexes: readonly number[]): void {
  for (const idx of indexes) {
    const spec = CLAIM_SPEC_BY_INDEX[idx];
    if (spec?.pii === true) {
      throw new SchemaError(`refusing to disclose PII-bearing attribute "${spec.name}"`);
    }
  }
}
