/**
 * The `BitstringStatusListCredential` ENVELOPE: its shape, its canonical form, and its Ed25519
 * signature.
 *
 * WHY THIS FILE EXISTS. `@stellaronramp/identity` verifies the status list ENCODING and reads the
 * BIT, and that is all it does — it is a no-network package and says so. Nothing in this repo has ever
 * fetched a status list URL, verified that document's OWN signature, checked its `validUntil`, cached
 * plain HTTP HAS AN MITM WHO CAN UN-REVOKE ANYBODY. An unsigned status list is the same hole with a
 * different attacker — anyone who can write to the origin, the CDN or the bucket.
 *
 * So the document is signed, and the signature is over a CANONICAL form, and the canonical form is
 * defined here rather than assumed.
 *
 * THE CRYPTOSUITE IS OURS AND IS NAMED AS SUCH. `stellaronramp-eddsa-jcs-2026`, not
 * `eddsa-jcs-2022`. Being precise about that is the honest thing to do and it costs nothing:
 *
 *   * WHAT WE MATCH: the W3C `eddsa-jcs-2022` construction, whose signing input is
 *     `sha256(canonical(proofConfig)) ‖ sha256(canonical(document-without-proof))` with canonical =
 *     JCS (RFC 8785), signed with Ed25519.
 *   * WHAT WE ADD: a 32-byte DOMAIN TAG at the front of the signing input. The chain side of this
 *     repo learned this lesson the expensive way — `attestation_message` and `revocation_message` in
 *     contracts/kyc-gate/src/lib.rs have distinct 32-byte domains precisely so neither can be
 *     reinterpreted as the other. The same issuer key must never produce a signature that is valid in
 *     two contexts, and "the proof config says which suite it is" is not a defence when the proof
 *     config is attacker-supplied input to the verifier.
 *   * WHAT THAT COSTS: a general-purpose W3C VC verifier will NOT verify our proof, and ours will not
 *     verify theirs. That is a real interoperability cost and it is the deliberate trade. Removing the
 *     domain tag and dropping to plain `eddsa-jcs-2022` is a ~5-line change if interop ever matters
 *     more than the separation; getting full interop ALSO needs JSON-LD canonicalisation for the
 *     `eddsa-rdfc-2022` suite, which needs `@digitalbazaar/rdf-canonize` — A NEW DEPENDENCY, and this
 *     run adds none.
 *
 * THE CANONICALISER IS RESTRICTED ON PURPOSE. It is JCS for the value subset this document uses —
 * ASCII object keys, strings, booleans, null, and small non-negative integers — and it REFUSES
 * anything outside that subset rather than silently emitting a non-canonical form. A full JCS
 * implementation has to reproduce ECMAScript `Number::toString` exactly for every double, and a
 * canonicaliser that is subtly wrong on floats is a signature that verifies on one runtime and not
 * another. Refusing a float is a build-time surprise; miscanonicalising one is a 3 a.m. surprise.
 */

import { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';

import { base64urlDecode, base64urlEncode } from '@stellaronramp/identity';
import type { BitstringStatusList, StatusPurpose } from '@stellaronramp/identity';

export class StatusCredentialError extends Error {
  override readonly name = 'StatusCredentialError';
}

/** Our cryptosuite identifier. See the module header for how it differs from `eddsa-jcs-2022`. */
export const STATUS_LIST_CRYPTOSUITE = 'stellaronramp-eddsa-jcs-2026';

/**
 * The 32-byte domain tag, exactly 32 bytes so it is self-delimiting and needs no length prefix — the
 * same property `ATTEST_DOMAIN` and `REVOKE_DOMAIN` have in src/chain/constants.ts. A load-time
 * assertion below makes a wrong length a module-load failure rather than a silently different
 * signature.
 */
export const STATUS_LIST_DOMAIN = 'stellaronramp.status-list.pub.v1';

const STATUS_LIST_DOMAIN_BYTES = Buffer.from(STATUS_LIST_DOMAIN, 'utf8');
if (STATUS_LIST_DOMAIN_BYTES.length !== 32) {
  throw new StatusCredentialError(
    `internal: STATUS_LIST_DOMAIN must be exactly 32 bytes, got ${STATUS_LIST_DOMAIN_BYTES.length}`,
  );
}

export const VC_V2_CONTEXT = 'https://www.w3.org/ns/credentials/v2';
export const BITSTRING_STATUS_LIST_CREDENTIAL_TYPE = 'BitstringStatusListCredential';
export const BITSTRING_STATUS_LIST_TYPE = 'BitstringStatusList';

export interface StatusListProof {
  readonly type: 'DataIntegrityProof';
  readonly cryptosuite: string;
  /** XSD dateTime, UTC, `Z`-suffixed. */
  readonly created: string;
  /** Which key signed. Pinned by the verifier; never used to FETCH a key. */
  readonly verificationMethod: string;
  readonly proofPurpose: 'assertionMethod';
  /** Multibase `u` ‖ base64url-no-pad of the 64-byte Ed25519 signature. */
  readonly proofValue: string;
}

/**
 * The signed document. `credentialSubject` is exactly identity's `BitstringStatusList` plus the two
 * W3C envelope fields, so `decodeStatusList` consumes it unchanged — which is the point: the publisher
 * must emit a list its own decoder accepts.
 */
export interface StatusListCredentialDocument {
  readonly '@context': readonly string[];
  readonly id: string;
  readonly type: readonly string[];
  readonly issuer: string;
  /** XSD dateTime, UTC. */
  readonly validFrom: string;
  /** XSD dateTime, UTC. */
  readonly validUntil: string;
  readonly credentialSubject: {
    readonly id: string;
    readonly type: string;
    readonly statusPurpose: string;
    readonly encodedList: string;
    readonly statusSize?: number;
    readonly statusMessage?: readonly { readonly status: string; readonly message: string }[];
  };
  readonly proof?: StatusListProof;
}

/* -------------------------------------------------------------------------- */
/* Canonicalisation                                                            */
/* -------------------------------------------------------------------------- */

/**
 * JCS (RFC 8785) restricted to the value subset above. Keys sorted by UTF-16 code unit (which is what
 * `Array.prototype.sort` on strings does and what JCS §3.2.3 requires), no whitespace, no trailing
 * commas.
 *
 * REFUSED, loudly: a non-integer number, a negative number, a number above `Number.MAX_SAFE_INTEGER`,
 * `undefined`, a function, a symbol, a bigint, a non-ASCII object key, and a circular structure.
 * Every one of those is a place a hand-rolled canonicaliser diverges from a real JCS implementation,
 * and a divergence is a signature that verifies here and fails there.
 */
export function canonicalJson(value: unknown, path = '$'): string {
  if (value === null) return 'null';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') {
    if (!Number.isInteger(value) || value < 0 || value > Number.MAX_SAFE_INTEGER) {
      throw new StatusCredentialError(
        `refusing to canonicalise ${path}: only non-negative safe integers are supported. A full ` +
          'JCS implementation must reproduce ECMAScript Number::toString for every double, and a ' +
          'canonicaliser that is subtly wrong on floats produces a signature that verifies on one ' +
          'runtime and not another.',
      );
    }
    return String(value);
  }
  if (typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) {
    return `[${value.map((v, i) => canonicalJson(v, `${path}[${i}]`)).join(',')}]`;
  }
  if (typeof value === 'object') {
    const bag = value as Record<string, unknown>;
    const keys = Object.keys(bag).filter((k) => bag[k] !== undefined);
    for (const key of keys) {
      // eslint-disable-next-line no-control-regex -- non-ASCII and control keys are refused
      if (!/^[\u0020-\u007e]*$/.test(key)) {
        throw new StatusCredentialError(
          `refusing to canonicalise ${path}: object key ${JSON.stringify(key)} is not printable ` +
            'ASCII, and JCS key ordering over non-BMP code points is where hand-rolled ' +
            'canonicalisers diverge',
        );
      }
    }
    keys.sort();
    const parts = keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(bag[k], `${path}.${k}`)}`);
    return `{${parts.join(',')}}`;
  }
  throw new StatusCredentialError(
    `refusing to canonicalise ${path}: ${typeof value} is not a JSON value`,
  );
}

/**
 * The exact bytes signed.
 *
 * `domain ‖ sha256(canonical(proofConfig)) ‖ sha256(canonical(documentWithoutProof))`.
 *
 * `proofConfig` is the proof object WITHOUT `proofValue` — i.e. the signature commits to its own
 * `cryptosuite`, `created`, `verificationMethod` and `proofPurpose`. Without that, an attacker who
 * obtained one valid signature could re-present it under a different `cryptosuite` or
 * `verificationMethod` label and a verifier that dispatched on those labels would be verifying one
 * thing while believing another. That is the same bug as the `X-Payload-Digest-Alg` header in
 * src/kyc/webhook.ts, one layer up.
 */
export function statusListSigningInput(
  document: StatusListCredentialDocument,
  proofConfig: Omit<StatusListProof, 'proofValue'>,
): Buffer {
  const { proof: _omitted, ...unsigned } = document;
  void _omitted;
  return Buffer.concat([
    STATUS_LIST_DOMAIN_BYTES,
    createHash('sha256').update(canonicalJson(proofConfig), 'utf8').digest(),
    createHash('sha256').update(canonicalJson(unsigned), 'utf8').digest(),
  ]);
}

/* -------------------------------------------------------------------------- */
/* Signing / verification                                                      */
/* -------------------------------------------------------------------------- */

/** Multibase `u` (base64url-no-pad), the same prefix identity's `encodedList` uses. */
const MULTIBASE_U = 'u';

export function encodeProofValue(signature: Uint8Array): string {
  return MULTIBASE_U + base64urlEncode(signature);
}

export function decodeProofValue(proofValue: unknown): Uint8Array {
  if (typeof proofValue !== 'string' || proofValue.length === 0) {
    throw new StatusCredentialError('status list proofValue must be a non-empty multibase string');
  }
  if (proofValue[0] !== MULTIBASE_U) {
    throw new StatusCredentialError(
      `status list proofValue must use the multibase "${MULTIBASE_U}" (base64url-no-pad) prefix, ` +
        `got "${String(proofValue[0])}"`,
    );
  }
  const bytes = base64urlDecode(proofValue.slice(1));
  if (bytes.length !== 64) {
    throw new StatusCredentialError(
      `status list proofValue decodes to ${bytes.length} bytes; an Ed25519 signature is 64`,
    );
  }
  return bytes;
}

/**
 * Sign a document. `privateKeyPkcs8Der` or a raw 32-byte seed — both accepted, because an operator
 * has one or the other and converting is fiddly enough that people get it wrong.
 */
export function signStatusListCredential(
  document: StatusListCredentialDocument,
  key: { readonly seed?: Uint8Array; readonly pkcs8Der?: Uint8Array },
  proofConfig: Omit<StatusListProof, 'proofValue'>,
): StatusListCredentialDocument {
  const privateKey =
    key.pkcs8Der !== undefined
      ? createPrivateKey({ key: Buffer.from(key.pkcs8Der), format: 'der', type: 'pkcs8' })
      : createPrivateKey({
          key: Buffer.concat([
            // PKCS#8 prologue for an Ed25519 private key: SEQUENCE(version 0, AlgorithmIdentifier
            // 1.3.101.112, OCTET STRING(OCTET STRING(seed))). Hard-coded because it is a constant
            // and because pulling in an ASN.1 library for 16 bytes would be a new dependency.
            Buffer.from('302e020100300506032b657004220420', 'hex'),
            Buffer.from(assertSeed(key.seed)),
          ]),
          format: 'der',
          type: 'pkcs8',
        });
  const signature = sign(null, statusListSigningInput(document, proofConfig), privateKey);
  return { ...document, proof: { ...proofConfig, proofValue: encodeProofValue(signature) } };
}

function assertSeed(seed: Uint8Array | undefined): Uint8Array {
  if (!(seed instanceof Uint8Array) || seed.length !== 32) {
    throw new StatusCredentialError(
      'a status list signing key must be a 32-byte Ed25519 seed or a PKCS#8 DER private key',
    );
  }
  return seed;
}

/**
 * Verify a document's own proof against a PINNED public key.
 *
 * "PINNED" IS THE LOAD-BEARING WORD. The key comes from the verifier's configuration, NEVER from the
 * document, NEVER from a `verificationMethod` URL, and NEVER from a DID resolution. A verifier that
 * dereferences `verificationMethod` to get the key it will check the signature with is verifying that
 * the document is self-consistent, which every forgery also is. `verificationMethod` is compared as a
 * LABEL against the expected one and is otherwise inert.
 *
 * FAILS CLOSED BY THROWING, always. There is no boolean return. identity's `verifyDetailed` turns a
 * resolver throw into `reason: 'status-list-invalid'`, i.e. `valid: false`; returning `false` here and
 * having one caller forget to check it would be a silent un-revoke of everybody.
 */
export function verifyStatusListCredential(
  document: unknown,
  expected: {
    readonly publicKeyRaw: Uint8Array;
    readonly issuer: string;
    readonly verificationMethod?: string;
  },
): StatusListCredentialDocument {
  const doc = assertDocumentShape(document);
  const proof = doc.proof;
  if (proof === undefined) {
    throw new StatusCredentialError(
      'refusing an UNSIGNED status list credential. An unsigned list means anyone who can write to ' +
        'the origin, the CDN or the bucket can un-revoke every holder at once (the status-list design note).',
    );
  }
  if (proof.type !== 'DataIntegrityProof') {
    throw new StatusCredentialError(
      `refusing a status list proof of type "${String(proof.type)}"; only DataIntegrityProof is ` +
        'supported',
    );
  }
  // PINNED SERVER-SIDE, exactly like the webhook algorithm allowlist. The document does not get to
  // choose which suite verifies it.
  if (proof.cryptosuite !== STATUS_LIST_CRYPTOSUITE) {
    throw new StatusCredentialError(
      `refusing a status list proof with cryptosuite "${String(proof.cryptosuite)}"; this verifier ` +
        `only accepts "${STATUS_LIST_CRYPTOSUITE}" and the suite is pinned server-side, never read ` +
        'from the document. Dispatching on a document-supplied algorithm name is the same bug class ' +
        'as trusting X-Payload-Digest-Alg.',
    );
  }
  if (proof.proofPurpose !== 'assertionMethod') {
    throw new StatusCredentialError(
      `refusing a status list proof whose proofPurpose is "${String(proof.proofPurpose)}"; a proof ` +
        'made for authentication or key agreement must not be reusable as an assertion',
    );
  }
  if (doc.issuer !== expected.issuer) {
    throw new StatusCredentialError(
      `refusing a status list credential issued by "${clamp(doc.issuer)}"; this verifier is pinned ` +
        `to "${clamp(expected.issuer)}". A correctly-signed list from the WRONG issuer is exactly ` +
        'what an attacker who controls any other issuer key would serve.',
    );
  }
  if (
    expected.verificationMethod !== undefined &&
    proof.verificationMethod !== expected.verificationMethod
  ) {
    throw new StatusCredentialError(
      `refusing a status list credential signed by verificationMethod ` +
        `"${clamp(String(proof.verificationMethod))}"; expected ` +
        `"${clamp(expected.verificationMethod)}"`,
    );
  }
  if (!(expected.publicKeyRaw instanceof Uint8Array) || expected.publicKeyRaw.length !== 32) {
    throw new StatusCredentialError(
      'refusing to verify a status list without a pinned 32-byte raw Ed25519 public key; a key read ' +
        'from the document itself would make every forgery self-consistent and therefore valid',
    );
  }
  const { proofValue, ...proofConfig } = proof;
  const signature = decodeProofValue(proofValue);
  const publicKey = createPublicKey({
    key: Buffer.concat([
      // SubjectPublicKeyInfo prologue for Ed25519: SEQUENCE(AlgorithmIdentifier 1.3.101.112,
      // BIT STRING(key)).
      Buffer.from('302a300506032b6570032100', 'hex'),
      Buffer.from(expected.publicKeyRaw),
    ]),
    format: 'der',
    type: 'spki',
  });
  const ok = verify(null, statusListSigningInput(doc, proofConfig), publicKey, signature);
  if (!ok) {
    throw new StatusCredentialError(
      'refusing a status list credential whose Ed25519 proof does not verify against the pinned ' +
        'issuer key. Either the document was tampered with in transit (which is the ' +
        'MITM-un-revokes-everybody case the status-list design note names) or the pinned key is wrong.',
    );
  }
  return doc;
}

/** The `credentialSubject`, in the exact shape identity's `decodeStatusList` consumes. */
export function toBitstringStatusList(doc: StatusListCredentialDocument): BitstringStatusList {
  const subject = doc.credentialSubject;
  const out: {
    statusPurpose: string;
    encodedList: string;
    statusSize?: number;
    statusMessage?: readonly { status: string; message: string }[];
  } = { statusPurpose: subject.statusPurpose, encodedList: subject.encodedList };
  if (subject.statusSize !== undefined) out.statusSize = subject.statusSize;
  if (subject.statusMessage !== undefined) out.statusMessage = subject.statusMessage;
  return out;
}

function assertDocumentShape(value: unknown): StatusListCredentialDocument {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new StatusCredentialError('a status list credential must be a JSON object');
  }
  const bag = value as Record<string, unknown>;
  const context = bag['@context'];
  if (!Array.isArray(context) || !context.includes(VC_V2_CONTEXT)) {
    throw new StatusCredentialError(
      `refusing a status list credential whose @context does not include "${VC_V2_CONTEXT}"`,
    );
  }
  const type = bag['type'];
  if (!Array.isArray(type) || !type.includes(BITSTRING_STATUS_LIST_CREDENTIAL_TYPE)) {
    throw new StatusCredentialError(
      `refusing a document that is not a ${BITSTRING_STATUS_LIST_CREDENTIAL_TYPE}; reading a bit ` +
        'out of some other credential type would be reading an attacker-chosen bitstring',
    );
  }
  for (const key of ['id', 'issuer', 'validFrom', 'validUntil'] as const) {
    if (typeof bag[key] !== 'string' || (bag[key] as string).length === 0) {
      throw new StatusCredentialError(
        `refusing a status list credential with no ${key}; ` +
          (key === 'validUntil'
            ? 'a list with no expiry is a list a stale mirror can serve forever'
            : 'the field is required by the envelope'),
      );
    }
  }
  const subject = bag['credentialSubject'];
  if (subject === null || typeof subject !== 'object' || Array.isArray(subject)) {
    throw new StatusCredentialError('a status list credential must carry a credentialSubject object');
  }
  const sub = subject as Record<string, unknown>;
  if (sub['type'] !== BITSTRING_STATUS_LIST_TYPE) {
    throw new StatusCredentialError(
      `refusing a credentialSubject of type "${String(sub['type'])}"; expected ` +
        `"${BITSTRING_STATUS_LIST_TYPE}"`,
    );
  }
  if (typeof sub['statusPurpose'] !== 'string' || typeof sub['encodedList'] !== 'string') {
    throw new StatusCredentialError(
      'a status list credentialSubject must carry a string statusPurpose and a string encodedList',
    );
  }
  return value as StatusListCredentialDocument;
}

function clamp(value: string): string {
  return value.length <= 96 ? value : `${value.slice(0, 96)}... (${value.length} chars)`;
}

/** `validFrom` / `validUntil` parsing, UTC, strict. */
export function parseXsdDateTime(value: unknown, field: string): number {
  if (typeof value !== 'string') {
    throw new StatusCredentialError(`status list ${field} must be a string`);
  }
  // `Z`-suffixed only. An offset-bearing or naive form would make the instant depend on how the
  // runtime feels about it, and this value gates whether a revocation list is still trustworthy.
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?Z$/.test(value)) {
    throw new StatusCredentialError(
      `status list ${field} must be a Z-suffixed UTC XSD dateTime, got "${clamp(value)}"; an ` +
        'offset-bearing or naive timestamp makes the validity window runtime-dependent',
    );
  }
  const ms = Date.parse(value);
  if (!Number.isFinite(ms)) {
    throw new StatusCredentialError(`status list ${field} "${clamp(value)}" is not a real instant`);
  }
  return Math.floor(ms / 1000);
}

/** Unix seconds -> the `Z`-suffixed form `parseXsdDateTime` accepts. */
export function toXsdDateTime(unixSeconds: number): string {
  if (!Number.isInteger(unixSeconds) || unixSeconds < 0) {
    throw new StatusCredentialError(
      `refusing to format ${String(unixSeconds)} as a dateTime; expected non-negative unix seconds`,
    );
  }
  return `${new Date(unixSeconds * 1000).toISOString().slice(0, 19)}Z`;
}

export type { StatusPurpose };
