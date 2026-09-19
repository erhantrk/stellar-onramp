/**
 * Credential issuance, proof derivation and proof verification.
 *
 * Everything here is off-chain and stateless. No network, no chain, no PII at rest: the caller
 */

import * as bbs from '@digitalbazaar/bbs-signatures';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js';

import {
  CIPHERSUITE,
  CLAIM_INDEX,
  CLAIM_SPEC_BY_INDEX,
  CREDENTIAL_HEADER,
  SCHEMA_ATTRIBUTE_COUNT,
  SCHEMA_VERSION,
  type ClaimName,
  type ClaimValue,
  type KycClaims,
  assertNoPiiDisclosed,
  decodeDisclosed,
  encodeClaims,
  normalizeIndexes,
} from './schema.js';
import {
  type ProofBinding,
  type ReplayGuard,
  assertValidBinding,
  bindingDigestHex,
  presentationHeaderFor,
} from './binding.js';
import { SIGNATURE_BYTES, expectedProofBytes, undisclosedCountFromProofBytes } from './points.js';
import {
  type BitstringStatusList,
  type StatusListResolver,
  type StatusPurpose,
  decodeStatusList,
  statusAt,
} from './status-list.js';

export class CredentialError extends Error {
  override readonly name = 'CredentialError';
}

export interface IssuerKeyPair {
  /** 32-byte scalar. */
  readonly secretKey: Uint8Array;
  /** 96-byte COMPRESSED G2 point. Use `decompressG2` before handing it to Soroban. */
  readonly publicKey: Uint8Array;
}

/**
 * A signed credential. Held client-side (IndexedDB) by the holder; the gateway does not retain
 */
export interface Credential {
  readonly schemaVersion: string;
  /** Canonical `name=value` messages, index i == CLAIM_INDEX[name]. */
  readonly messages: readonly string[];
  /** 80 bytes: compressed G1 ‖ scalar. */
  readonly signature: Uint8Array;
  /** 96-byte compressed G2. Carried so the holder can verify without a directory lookup. */
  readonly issuerPublicKey: Uint8Array;
  readonly claims: KycClaims;
}

/** A derived selective-disclosure presentation. Safe to hand to a relying party verbatim. */
export interface Proof {
  readonly schemaVersion: string;
  /** `144 + 32·(4 + U)` bytes. */
  readonly proof: Uint8Array;
  /** Ascending, unique. */
  readonly disclosedIndexes: readonly number[];
  /** Canonical messages, parallel to `disclosedIndexes`. */
  readonly disclosedMessages: readonly string[];
  /** Total messages in the credential — needed to reconstruct the hidden index set. */
  readonly totalMessages: number;
  /** MANDATORY. Without it there is no proof; see binding.ts. */
  readonly binding: ProofBinding;
}

/** Deterministic issuer key generation. `seed` must be 32 bytes; omit for a random key. */
export async function generateIssuerKeyPair(seed?: Uint8Array): Promise<IssuerKeyPair> {
  if (seed !== undefined && seed.length !== 32) {
    throw new CredentialError('issuer key seed must be 32 bytes');
  }
  const kp = await bbs.generateKeyPair(
    seed === undefined ? { ciphersuite: CIPHERSUITE } : { seed, ciphersuite: CIPHERSUITE },
  );
  return { secretKey: kp.secretKey, publicKey: kp.publicKey };
}

export async function issuerPublicKey(secretKey: Uint8Array): Promise<Uint8Array> {
  return bbs.secretKeyToPublicKey({ secretKey, ciphersuite: CIPHERSUITE });
}

/**
 * Stable 32-byte hex issuer id: sha256 over the COMPRESSED G2 public key. Goes in claim index 1.
 * Compressed, not uncompressed, so the id is stable regardless of which wire form is in hand.
 */
export function issuerIdFromPublicKey(publicKey: Uint8Array): string {
  return bytesToHex(sha256(publicKey));
}

/**
 * Issue a credential: BBS+ multi-message signature over all 12 canonical messages.
 *
 * The `header` is the constant `CREDENTIAL_HEADER`, not per-credential data, so the on-chain
 * verifier can recompute `domain` from the schema version alone rather than trusting an input.
 */
export async function issue(
  claims: KycClaims,
  issuerSecretKey: Uint8Array,
): Promise<Credential> {
  if (!(issuerSecretKey instanceof Uint8Array) || issuerSecretKey.length !== 32) {
    throw new CredentialError('issuerSecretKey must be a 32-byte Uint8Array');
  }
  if (claims.schemaVersion !== SCHEMA_VERSION) {
    throw new CredentialError(
      `claims.schemaVersion must be "${SCHEMA_VERSION}", got "${claims.schemaVersion}"`,
    );
  }
  if (claims.expiresAt <= claims.issuedAt) {
    throw new CredentialError('claims.expiresAt must be strictly after claims.issuedAt');
  }

  const messages = encodeClaims(claims);
  if (messages.length !== SCHEMA_ATTRIBUTE_COUNT) {
    throw new CredentialError('internal: encoded message count mismatch');
  }

  const publicKey = await issuerPublicKey(issuerSecretKey);
  if (claims.issuerId !== issuerIdFromPublicKey(publicKey)) {
    // Catches "signed with the wrong key" at issuance instead of at every future verification.
    throw new CredentialError('claims.issuerId does not match the signing key');
  }

  const signature = await bbs.sign({
    secretKey: issuerSecretKey,
    publicKey,
    header: utf8ToBytes(CREDENTIAL_HEADER),
    messages: messages.map((m) => utf8ToBytes(m)),
    ciphersuite: CIPHERSUITE,
  });
  if (signature.length !== SIGNATURE_BYTES) {
    throw new CredentialError(`internal: expected ${SIGNATURE_BYTES}-byte signature`);
  }

  return {
    schemaVersion: SCHEMA_VERSION,
    messages,
    signature,
    issuerPublicKey: publicKey,
    claims,
  };
}

/** Self-check a credential against the issuer key. Holders should run this on receipt. */
export async function verifyCredential(credential: Credential): Promise<boolean> {
  try {
    return await bbs.verifySignature({
      publicKey: credential.issuerPublicKey,
      signature: credential.signature,
      header: utf8ToBytes(CREDENTIAL_HEADER),
      messages: credential.messages.map((m) => utf8ToBytes(m)),
      ciphersuite: CIPHERSUITE,
    });
  } catch {
    return false;
  }
}

/**
 * Derive a selective-disclosure proof.
 *
 * `binding` is REQUIRED and the raw `presentationHeader` is deliberately not a parameter —
 * there is no code path that produces an unbound proof.
 */
export async function derive(
  credential: Credential,
  revealedIndices: readonly number[],
  binding: ProofBinding,
): Promise<Proof> {
  if (credential.schemaVersion !== SCHEMA_VERSION) {
    throw new CredentialError(`unsupported credential schema v${credential.schemaVersion}`);
  }
  assertValidBinding(binding);
  const disclosedIndexes = normalizeIndexes(revealedIndices);

  const messages = credential.messages.map((m) => utf8ToBytes(m));
  const proof = await bbs.deriveProof({
    publicKey: credential.issuerPublicKey,
    signature: credential.signature,
    header: utf8ToBytes(CREDENTIAL_HEADER),
    messages,
    presentationHeader: presentationHeaderFor(binding),
    disclosedMessageIndexes: [...disclosedIndexes],
    ciphersuite: CIPHERSUITE,
  });

  const u = credential.messages.length - disclosedIndexes.length;
  if (proof.length !== expectedProofBytes(u)) {
    throw new CredentialError(
      `internal: proof is ${proof.length} bytes, size law predicts ${expectedProofBytes(u)}`,
    );
  }

  const disclosedMessages = disclosedIndexes.map((i) => {
    const m = credential.messages[i];
    if (m === undefined) throw new CredentialError(`credential has no message at index ${i}`);
    return m;
  });

  return {
    schemaVersion: credential.schemaVersion,
    proof,
    disclosedIndexes,
    disclosedMessages,
    totalMessages: credential.messages.length,
    binding,
  };
}

/**
 * The one and only way to switch a safety check OFF. It is a required, explicit, greppable value
 * because the previous design — every check opt-IN through a bag that defaulted to `{}` — meant
 * the obvious three-argument `verify(proof, pk, binding)` checked NOTHING beyond the signature:
 * not presentation expiry, not credential expiry, not the subject, not revocation, not replay
 *
 * Omission is now impossible: every field below is REQUIRED. A caller who genuinely has no clock,
 * and greps out of a codebase in one command:
 *
 *     rg 'UNSAFE_SKIP|UNSAFE_NO_CHECKS' -- src/
 *
 * The value is namespaced so it cannot be produced by accident from user data (a `subjectBinding`
 * is 64 hex characters; a ledger is a number).
 */
export const UNSAFE_SKIP = '@stellaronramp/identity:UNSAFE_SKIP' as const;
export type UnsafeSkip = typeof UNSAFE_SKIP;

export interface VerifyOptions {
  /**
   * REQUIRED. Current ledger sequence; a proof whose `binding.ledgerExpiry` is below it is
   * rejected. Pass `UNSAFE_SKIP` if you truly have no ledger view — and then own the fact that
   * an ancient challenge is now indistinguishable from a fresh one.
   *
   * NOTE this bounds the PRESENTATION, not the credential: `ledgerExpiry` is chosen by the
   * relying party when it issues the challenge, so it says nothing about how old the credential
   * is. Credential lifetime is `currentTime` below. They are different checks and you need both.
   */
  readonly currentLedger: number | UnsafeSkip;
  /**
   * REQUIRED. Unix seconds. Enforces the CREDENTIAL's own lifetime against claim index 4
   * (`expiresAt`).
   *
   * Fails closed: if this is a number and the proof does not disclose `expiresAt`, verification is
   * rejected rather than silently skipped. Without that, a relying party that asks for expiry
   * enforcement over a proof that hides index 4 would get `valid: true` and believe it had
   * checked something. Compose `credentialAudit()` into your predicate to disclose it.
   */
  readonly currentTime: number | UnsafeSkip;
  /**
   * REQUIRED. The `sha256(wallet ‖ salt)` commitment the relying party expects at claim index 5,
   * i.e. the output of `computeSubjectBinding(binding.walletAddress, holderSalt)`.
   *
   * Also fails closed when index 5 is not disclosed. Without this check a proof only says "SOME
   * credential from this issuer is over 18" — one KYC'd holder can gate arbitrarily many wallets.
   */
  readonly expectedSubjectBinding: string | UnsafeSkip;
  /**
   * REQUIRED. Revocation. Either the already-resolved W3C Bitstring Status List, or a resolver
   * CALLBACK that produces one — this package makes no network calls, so dereferencing the
   * `statusListCredential` URL and verifying its proof is the caller's job (see status-list.ts).
   *
   * Fails closed: supplying a list (or resolver) over a proof that does not disclose
   * `revocationIndex` (index 2) is rejected, exactly like `currentTime` over a hidden index 4.
   * Compose `credentialAudit()` into your predicate, or use `gateOnrampPredicate()`.
   *
   * `UNSAFE_SKIP` means "I accept revoked credentials". It exists so that not checking revocation
   */
  readonly statusList: BitstringStatusList | StatusListResolver | UnsafeSkip;
  /**
   * REQUIRED. Single-use nonce enforcement. Consumed only on an otherwise-successful
   * verification, so a malformed or revoked proof cannot burn a live nonce.
   */
  readonly replayGuard: ReplayGuard | UnsafeSkip;
  /**
   * Which status purpose `statusList` is expected to be. Defaults to `'revocation'`.
   */
  readonly statusPurpose?: StatusPurpose;
  /**
   * REQUIRED. Expected disclosed values. A proof that verifies but says `over18=false` is still
   * a NO — the BBS+ mathematics only says the issuer signed the claim, never that the claim says
   * what you wanted.
   *
   * This was the LAST optional field, and leaving it optional was the open half of
   * that `checkPredicate()` always fills it from `predicate.expect`, which is true and which does
   * close the hole *for that door*. But `verifyDetailed()` and `verify()` are both exported from
   * `src/index.ts`, and a relying party that called either one, named all five safety fields and
   * forgot this one accepted a genuine, unexpired, unrevoked, correctly-wallet-bound credential
   * asserting `over18=false, notSanctioned=false` — a sanctioned minor, `valid: true`. That was
   * demonstrated by execution, not argued.
   *
   * `UNSAFE_SKIP` means "I am not checking any disclosed value", which is legitimate for a purely
   * structural verification (fixture replay, `credentialAudit()`-only presentations, cryptography
   * tooling). It is spelled out loud for the same reason the other five are: an omitted check has
   * to be a visible act, not a default.
   *
   * `{}` is accepted and is behaviourally identical to `UNSAFE_SKIP` — `checkPredicate` forwards
   * `predicate.expect` verbatim and a caller-authored predicate may legitimately have no value
   * expectations. `{}` is therefore the one remaining silent way to disable this check; it is not
   */
  readonly expectedClaims?: Partial<Record<ClaimName, ClaimValue>> | UnsafeSkip;
  /**
   * REQUIRED. The EXACT set of indexes this verification asked the holder to reveal. A proof that
   * reveals MORE is rejected.
   *
   * Why "more" is a failure at all, since it verifies and every value checks out: over-disclosure
   * is a HOLDER-privacy failure rather than a relying-party security failure, and the relying
   * party is the only one in a position to refuse it. A gate that asks for `{6,8}` and accepts a
   * full-disclosure proof has taken `issuedAt`, `revocationIndex` and `subjectBinding` it never
   * asked for and now holds a correlation handle it has no policy for. The holder cannot stop it;
   * their SDK is the thing that over-disclosed.
   *
   * `checkPredicate()` has always pinned this from `predicate.disclose` and was the documented
   * express the ask at all — this field is that way, and it is REQUIRED for the same reason the
   * other six are: the failure mode of an optional safety field is that it gets left out.
   *
   * `UNSAFE_SKIP` means "any disclosure set is acceptable", which is legitimate for fixture replay
   * and cryptography tooling and is what `UNSAFE_NO_CHECKS` uses. `[]` is NOT a synonym: it means
   * "reveal nothing", and a proof disclosing anything at all fails against it.
   */
  readonly expectedDisclosedIndexes: readonly number[] | UnsafeSkip;
}

/**
 * Every check disabled. For tests, for fixture replay, and for cryptography-only tooling that
 * genuinely has no policy context. NEVER in a production verification path — the identifier is
 *
 * Typed as a FULL `VerifyOptions`. It spreads into a `checkPredicate` bag: that parameter is
 * `Omit<VerifyOptions,'expectedClaims'>`, and a named constant carrying one extra property is
 * assignable to it — excess-property checking only bites on fresh object literals. So both
 *
 *     verifyDetailed(proof, pk, binding, UNSAFE_NO_CHECKS)
 *     checkPredicate(proof, pred, pk, binding, { ...UNSAFE_NO_CHECKS })
 *
 * exactly zero edits.
 */
export const UNSAFE_NO_CHECKS: VerifyOptions = {
  currentLedger: UNSAFE_SKIP,
  currentTime: UNSAFE_SKIP,
  expectedSubjectBinding: UNSAFE_SKIP,
  statusList: UNSAFE_SKIP,
  replayGuard: UNSAFE_SKIP,
  expectedClaims: UNSAFE_SKIP,
  expectedDisclosedIndexes: UNSAFE_SKIP,
};

/** Tolerance for issuer/verifier clock skew when sanity-checking `issuedAt`, in seconds. */
export const ISSUANCE_CLOCK_SKEW_SECONDS = 300;

export type VerifyFailure =
  | 'schema-version'
  | 'binding-mismatch'
  | 'binding-invalid'
  | 'expired'
  | 'credential-expired'
  | 'subject-mismatch'
  | 'malformed-proof'
  /**
   * "The set of messages this proof reveals is not the set this verification needs."
   *
   * unfragmented on purpose — splitting it would widen this public union, break existing alert
   * rules, and tell an operator nothing `detail` does not already say). Nine are in this file and
   * one is in `predicates.ts`; the count was EIGHT until the survey-27/28/29 pass added two, and
   * this enumeration is the operator's triage guide, so it is kept exact rather than approximate.
   * Triage by `detail`:
   *
   *   ATTACK / MALFORMED PRESENTATION
   *     "totalMessages N != schema size"                     — the proof claims a different schema
   *     "disclosed index/message length mismatch"            — parallel arrays disagree
   *     "disclosed indexes must be strictly ascending"       — message-substitution attempt
   *     "proof encodes U=n but m of 12 indexes are ..."      — claiming an unrevealed index
   *     "predicate \"L\" wants indexes [...], proof discl..." — answers a different question
   *     "refusing a proof that discloses a PII-bearing ..."  — holder revealed an attribute this
   *                                                            verifier refuses to receive
   *     "expectedDisclosedIndexes [...] does not match ..."  — holder revealed a different set
   *                                                            than the caller asked for
   *   CALLER MISCONFIGURATION (the check was demanded over a proof that hides its input)
   *     "... does not disclose expiresAt (index 4)"          — currentTime over a hidden 4
   *     "... does not disclose subjectBinding (index 5)"     — expectedSubjectBinding over hidden 5
   *     "... does not disclose revocationIndex (index 2)"    — statusList over a hidden 2
   *
   * Both new strings are ATTACK entries, not caller misconfiguration: the caller's demand is
   * well-formed in each and it is the HOLDER's disclosure set that is wrong.
   *
   * Those ten strings are load-bearing for triage, so they are pinned by
   * exclusive. Rewording one is a deliberate act with a failing test attached.
   */
  | 'disclosure-shape'
  | 'unknown-index'
  | 'message-index-mismatch'
  | 'claim-mismatch'
  /** The status list says this credential's entry is set. The holder is revoked/suspended. */
  | 'revoked'
  /**
   * The status list itself could not be used: unknown or mismatched `statusPurpose`, bad
   * multibase/base64url/GZIP, shorter than the 131,072-entry spec minimum, an index outside its
   * range, or a resolver that threw. Distinct from `revoked` (the holder is fine, our
   * infrastructure is not) and from `disclosure-shape` (the caller's predicate under-discloses),
   * because those three need completely different operational responses.
   */
  | 'status-list-invalid'
  | 'replayed'
  | 'bbs-invalid'
  | 'error';

export interface VerifyResult {
  readonly valid: boolean;
  readonly reason?: VerifyFailure;
  readonly detail?: string;
  /** Decoded disclosed claims — only populated when `valid`. */
  readonly claims?: Partial<Record<ClaimName, ClaimValue>>;
}

/**
 * Full verification. Returns a reason on failure, which matters because "the BBS+ math failed"
 * and "the nonce was replayed" need very different operational responses.
 *
 * Order is deliberate: cheap structural and binding checks first, the ~10 ms BBS+ ProofVerify
 * next, then the disclosed-value policy checks (cheapest first — string compares before the
 * status-list GZIP), and replay consumption after everything else so a malformed, expired or
 * revoked proof cannot burn a nonce.
 *
 * `options` is REQUIRED and every safety field inside it is REQUIRED. See `UNSAFE_SKIP`.
 */
export async function verifyDetailed(
  proof: Proof,
  issuerPubKey: Uint8Array,
  expectedBinding: ProofBinding,
  options: VerifyOptions,
): Promise<VerifyResult> {
  try {
    if (proof.schemaVersion !== SCHEMA_VERSION) {
      return fail('schema-version', `proof is schema v${proof.schemaVersion}`);
    }

    try {
      assertValidBinding(expectedBinding);
    } catch (e) {
      return fail('binding-invalid', String((e as Error).message));
    }

    // The proof carries its own binding; it must be byte-identical to what we demanded.
    // Comparing digests catches a swapped contractId / walletAddress / nonce / network.
    let proofDigest: string;
    try {
      proofDigest = bindingDigestHex(proof.binding);
    } catch (e) {
      return fail('binding-invalid', String((e as Error).message));
    }
    if (proofDigest !== bindingDigestHex(expectedBinding)) {
      return fail('binding-mismatch', 'proof binding does not match expected binding');
    }

    if (options.currentLedger !== UNSAFE_SKIP) {
      if (!Number.isInteger(options.currentLedger) || options.currentLedger < 0) {
        return fail(
          'error',
          'options.currentLedger must be a non-negative integer ledger sequence or UNSAFE_SKIP',
        );
      }
      if (options.currentLedger > expectedBinding.ledgerExpiry) {
        return fail(
          'expired',
          `ledger ${options.currentLedger} is past expiry ${expectedBinding.ledgerExpiry}`,
        );
      }
    }

    if (proof.totalMessages !== SCHEMA_ATTRIBUTE_COUNT) {
      return fail('disclosure-shape', `totalMessages ${proof.totalMessages} != schema size`);
    }
    if (proof.disclosedIndexes.length !== proof.disclosedMessages.length) {
      return fail('disclosure-shape', 'disclosed index/message length mismatch');
    }
    // Ascending + unique + in-range. A repeated or out-of-order index is a substitution attempt,
    // and the library would otherwise mis-associate messages with indexes.
    for (let i = 0; i < proof.disclosedIndexes.length; i++) {
      const idx = proof.disclosedIndexes[i] as number;
      if (!Number.isInteger(idx) || idx < 0 || idx >= SCHEMA_ATTRIBUTE_COUNT) {
        return fail('unknown-index', `index ${idx} not in schema`);
      }
      if (i > 0 && idx <= (proof.disclosedIndexes[i - 1] as number)) {
        return fail('disclosure-shape', 'disclosed indexes must be strictly ascending');
      }
    }

    // run it via `normalizeIndexes`, but a verifier that only ran it on its own derivations was
    // policing itself and nobody else: a proof arrives from a HOLDER, and a holder running an old
    // or hostile SDK is exactly the party the guard is aimed at. A no-op on schema v1 (nothing is
    // `pii: true`) and deliberately so — it is here for the v2 append, which is when an
    // asymmetric guardrail would silently stop covering the only direction that matters.
    try {
      assertNoPiiDisclosed(proof.disclosedIndexes);
    } catch (e) {
      return fail(
        'disclosure-shape',
        `refusing a proof that discloses a PII-bearing attribute: ${String((e as Error).message)}`,
      );
    }

    // The disclosure set is EXACTLY what was asked for — no more (a privacy failure) and no less
    // (which the per-check "does not disclose index N" guards would catch anyway, less clearly).
    // Structural, so it sits here with the other structural checks rather than after ProofVerify:
    // the index set is public in the presentation and nothing about rejecting it early leaks.
    if (options.expectedDisclosedIndexes !== UNSAFE_SKIP) {
      const want: unknown = options.expectedDisclosedIndexes;
      // An INDEXED loop, not `.some(...)`: `Array.prototype.some` SKIPS HOLES, so the sparse
      // `[6, , 8]` walked straight past an "every element is an in-range integer" gate built on
      // it and was caught only by the later set comparison — landing in `disclosure-shape` when
      // the comment right below promises `'error'` with the rest of the plain-JS mistakes
      let malformed = !Array.isArray(want);
      if (!malformed) {
        const arr = want as readonly unknown[];
        for (let i = 0; i < arr.length; i++) {
          const v = arr[i];
          if (!Number.isInteger(v) || (v as number) < 0 || (v as number) >= SCHEMA_ATTRIBUTE_COUNT) {
            malformed = true;
            break;
          }
        }
      }
      if (malformed) {
        // FAIL CLOSED on a bag a plain-JS caller filled in wrongly, exactly like expectedClaims:
        // `undefined`, a Set, a string, a float index, a hole are all refused rather than read as
        // "any disclosure set is fine".
        return fail(
          'error',
          'options.expectedDisclosedIndexes must be an array of in-range integer claim indexes ' +
            `(0..${SCHEMA_ATTRIBUTE_COUNT - 1}) or UNSAFE_SKIP; note [] means "reveal nothing", ` +
            'not "skip the check"',
        );
      }
      const wantSorted = [...(want as number[])].sort((a, b) => a - b);
      const got = [...proof.disclosedIndexes];
      if (wantSorted.length !== got.length || wantSorted.some((v, i) => v !== got[i])) {
        return fail(
          'disclosure-shape',
          `expectedDisclosedIndexes [${wantSorted.join(',')}] does not match the proof's ` +
            `disclosure set [${got.join(',')}]`,
        );
      }
    }

    // The proof's own length pins U. If the claimed disclosure set disagrees with the byte
    // length, someone is trying to claim an index they did not actually reveal.
    let u: number;
    try {
      u = undisclosedCountFromProofBytes(proof.proof.length);
    } catch (e) {
      return fail('malformed-proof', String((e as Error).message));
    }
    if (u !== SCHEMA_ATTRIBUTE_COUNT - proof.disclosedIndexes.length) {
      return fail(
        'disclosure-shape',
        `proof encodes U=${u} but ${proof.disclosedIndexes.length} of ` +
          `${SCHEMA_ATTRIBUTE_COUNT} indexes are claimed disclosed`,
      );
    }

    // Each disclosed message must name the attribute its index says it should.
    let decoded: Partial<Record<ClaimName, ClaimValue>>;
    try {
      decoded = decodeDisclosed(proof.disclosedIndexes, proof.disclosedMessages);
    } catch (e) {
      return fail('message-index-mismatch', String((e as Error).message));
    }

    // ProofVerify does not only RETURN false — it THROWS on bytes it cannot decode at all, e.g.
    // "bad point: not in prime-order subgroup" for a flipped bit inside a compressed G1. Those
    // bytes came from a HOLDER, so the throw is an ATTACK, and letting it fall through to the
    // outer catch put it in `reason: 'error'` — the same bucket as "your options bag is a Map".
    // An operator alerting on tampered proofs could not see them. `malformed-proof` is the bucket
    // that already means "these bytes are not a proof"; the frozen `tampered-abar` vector has
    // declared `bbs-invalid-or-malformed` since before this line existed.
    let ok: boolean;
    try {
      ok = await bbs.verifyProof({
        publicKey: issuerPubKey,
        proof: proof.proof,
        header: utf8ToBytes(CREDENTIAL_HEADER),
        presentationHeader: presentationHeaderFor(expectedBinding),
        disclosedMessages: proof.disclosedMessages.map((m) => utf8ToBytes(m)),
        disclosedMessageIndexes: [...proof.disclosedIndexes],
        ciphersuite: CIPHERSUITE,
      });
    } catch (e) {
      return fail('malformed-proof', `BBS+ ProofVerify threw: ${String((e as Error)?.message ?? e)}`);
    }
    if (!ok) return fail('bbs-invalid', 'BBS+ ProofVerify returned false');

    // Everything below reads DISCLOSED VALUES, so it has to sit after ProofVerify — before it,
    // `decoded` is just attacker-supplied text that happens to parse.

    // The SIGNED schema version, when the presentation discloses it. `proof.schemaVersion` above
    // is a self-asserted label the presenter can set to anything; only index 0 is under the
    // issuer's signature. The primary cross-version defence is CREDENTIAL_HEADER (it carries the
    // version and is hashed into `domain`, so a v2-headered credential fails ProofVerify) — this
    // is the second lock, for the case where two schemas ever share a header.
    if (decoded.schemaVersion !== undefined && decoded.schemaVersion !== SCHEMA_VERSION) {
      return fail(
        'schema-version',
        `credential is signed as schema v${String(decoded.schemaVersion)}, verifier is v${SCHEMA_VERSION}`,
      );
    }

    // The SIGNED issuer id, when disclosed, must be the key we just verified against. Catches a
    // credential that names one issuer in its body while being signed by another.
    if (decoded.issuerId !== undefined && decoded.issuerId !== issuerIdFromPublicKey(issuerPubKey)) {
      return fail('claim-mismatch', 'disclosed issuerId does not match the verifying public key');
    }

    // Credential lifetime. Distinct from the presentation's ledgerExpiry above: a holder whose
    // credential died years ago can always mint a fresh binding with a far-future ledgerExpiry,
    // so the ledger check alone constrains nothing about credential age.
    if (options.currentTime !== UNSAFE_SKIP) {
      if (!Number.isFinite(options.currentTime)) {
        return fail('error', 'options.currentTime must be a finite unix-seconds number or UNSAFE_SKIP');
      }
      const expiresAt = decoded.expiresAt;
      if (typeof expiresAt !== 'number') {
        return fail(
          'disclosure-shape',
          'expiry enforcement requested but the proof does not disclose expiresAt (index 4); ' +
            'compose credentialAudit() into the predicate',
        );
      }
      if (options.currentTime > expiresAt) {
        return fail(
          'credential-expired',
          `credential expired at ${expiresAt}, current time ${options.currentTime}`,
        );
      }
      const issuedAt = decoded.issuedAt;
      if (
        typeof issuedAt === 'number' &&
        issuedAt > options.currentTime + ISSUANCE_CLOCK_SKEW_SECONDS
      ) {
        return fail('credential-expired', `credential issuedAt ${issuedAt} is in the future`);
      }
    }

    // Subject binding: is this credential actually this wallet's own?
    if (options.expectedSubjectBinding !== UNSAFE_SKIP) {
      const subject = decoded.subjectBinding;
      if (typeof subject !== 'string') {
        return fail(
          'disclosure-shape',
          'subject-binding enforcement requested but the proof does not disclose ' +
            'subjectBinding (index 5); compose credentialAudit() into the predicate',
        );
      }
      if (subject !== options.expectedSubjectBinding) {
        return fail('subject-mismatch', 'credential is bound to a different subject');
      }
    }

    // Disclosed-VALUE policy. `UNSAFE_SKIP` is the only way to switch it off from TypeScript;
    // a plain-JS caller who omits the field entirely lands in the guard below and is REJECTED
    // half). `undefined` is emphatically not "skip" here.
    if (options.expectedClaims !== undefined && options.expectedClaims !== UNSAFE_SKIP) {
      const expected: unknown = options.expectedClaims;
      //     expected === null || typeof expected !== 'object' || Array.isArray(expected)
      // which rejects `undefined`, `null`, `[]`, `0`, `'over18'` and functions — but ACCEPTS any
      // other object and then reads it with `Object.entries`. `Object.entries(new Map(...))` is
      // `[]`, so a plain-JS caller who wrote a REAL policy as
      //     expectedClaims: new Map([['over18', true], ['notSanctioned', true]])
      // got `valid: true` on a credential asserting `over18=false, notSanctioned=false` — a
      // sanctioned minor — with no error and no way to tell the check had not run. Demonstrated
      // by execution before this line existed. The same held for `new Set`, `new Date`,
      // `Promise.resolve({over18:true})` and any object carrying its claims on a PROTOTYPE.
      //
      // `expectedClaims` is documented as a claim-name -> value MAP, so require a plain object:
      // `{}`, an object literal, `JSON.parse(...)` and `Object.create(null)` all pass; every
      // exotic carrier above is now `reason: 'error'`. FAIL-CLOSED in every case — nothing that
      // used to be rejected is now accepted.
      //
      // COST, stated plainly: a caller passing a CLASS INSTANCE (`new Policy()` with own
      // enumerable fields) used to work correctly and is now rejected. That is a behaviour break
      // for an unusual-but-legitimate caller. It is paid now, in the same release as the
      // `expectedClaims`-required API break, rather than after the SDK ships.
      const proto: unknown =
        expected !== null && typeof expected === 'object' ? Object.getPrototypeOf(expected) : false;
      if (
        expected === null ||
        typeof expected !== 'object' ||
        Array.isArray(expected) ||
        (proto !== Object.prototype && proto !== null)
      ) {
        return fail(
          'error',
          'options.expectedClaims must be a PLAIN claim-name -> value object (possibly {}) or ' +
            'UNSAFE_SKIP; a Map, Set, Date, Promise, array or class instance is refused rather ' +
            'than silently read as "no value policy"',
        );
      }
      for (const [name, want] of Object.entries(options.expectedClaims)) {
        if (want === undefined) continue;
        const got = decoded[name as ClaimName];
        if (got === undefined) {
          return fail('claim-mismatch', `claim "${name}" was not disclosed`);
        }
        if (got !== want) {
          return fail('claim-mismatch', `claim "${name}" is ${String(got)}, expected ${String(want)}`);
        }
      }
    }

    // Revocation, last of the policy checks because it is the only one that decompresses 16 KB.
    // W3C Bitstring Status List v1.0 §3.2 Validate Algorithm, minus step 4 (the URL dereference),
    // which belongs to the caller because this package makes no network calls.
    if (options.statusList !== UNSAFE_SKIP) {
      const purpose: StatusPurpose = options.statusPurpose ?? 'revocation';
      const revocationIndex = decoded.revocationIndex;
      if (typeof revocationIndex !== 'number') {
        // FAIL CLOSED, same shape and same reason as the currentTime / expectedSubjectBinding
        // branches above: a caller who asked for revocation checking and got `valid: true`
        // without one having happened is the exact failure this whole file guards against.
        return fail(
          'disclosure-shape',
          'revocation checking requested but the proof does not disclose revocationIndex ' +
            '(index 2); compose credentialAudit() into the predicate, or use gateOnrampPredicate()',
        );
      }
      let resolved: BitstringStatusList;
      try {
        resolved =
          typeof options.statusList === 'function'
            ? await options.statusList({
                revocationIndex,
                issuerId: typeof decoded.issuerId === 'string' ? decoded.issuerId : undefined,
                statusPurpose: purpose,
              })
            : options.statusList;
      } catch (e) {
        return fail(
          'status-list-invalid',
          `status list resolver failed: ${String((e as Error)?.message ?? e)}`,
        );
      }
      let status: number;
      try {
        const list = await decodeStatusList(resolved, { expectedPurpose: purpose });
        status = statusAt(list, revocationIndex);
      } catch (e) {
        return fail('status-list-invalid', String((e as Error)?.message ?? e));
      }
      // §3.2 step 13: "If status is 0, set the valid key in result to true; otherwise, set it
      // to false."
      if (status !== 0) {
        return fail(
          'revoked',
          `credential is ${purpose === 'suspension' ? 'suspended' : 'revoked'}: status ${status} ` +
            `at ${purpose} list index ${revocationIndex}`,
        );
      }
    }

    // Burn the nonce last: a proof that failed for any other reason must not consume it,
    // otherwise a bystander could grief a holder by replaying garbage.
    if (options.replayGuard !== UNSAFE_SKIP && !options.replayGuard.consume(expectedBinding)) {
      return fail('replayed', 'binding nonce already consumed');
    }

    return { valid: true, claims: decoded };
  } catch (e) {
    return fail('error', String((e as Error)?.message ?? e));
  }
}

function fail(reason: VerifyFailure, detail: string): VerifyResult {
  return { valid: false, reason, detail };
}

/**
 * Boolean verification. `verifyDetailed` with the reason thrown away.
 *
 * argument is gone — it is `options.expectedClaims` now — and `options` is REQUIRED. There is no
 * longer a three-argument call, because the three-argument call checked nothing.
 *
 * `checkPredicate()` remains the easier door — it fills BOTH `expectedClaims` and
 * `expectedDisclosedIndexes` from the predicate, so the disclosure set and the value expectations
 * cannot drift apart — but it is no longer the ONLY door that pins the disclosure set.
 */
export async function verify(
  proof: Proof,
  issuerPubKey: Uint8Array,
  expectedBinding: ProofBinding,
  options: VerifyOptions,
): Promise<boolean> {
  const result = await verifyDetailed(proof, issuerPubKey, expectedBinding, options);
  return result.valid;
}

/* -------------------------------------------------------------------------- */
/* Serialisation                                                               */
/* -------------------------------------------------------------------------- */

export interface SerializedCredential {
  readonly schemaVersion: string;
  readonly messages: readonly string[];
  readonly signature: string;
  readonly issuerPublicKey: string;
  readonly claims: KycClaims;
}

export interface SerializedProof {
  readonly schemaVersion: string;
  readonly proof: string;
  readonly disclosedIndexes: readonly number[];
  readonly disclosedMessages: readonly string[];
  readonly totalMessages: number;
  readonly binding: ProofBinding;
}

export function serializeCredential(c: Credential): SerializedCredential {
  return {
    schemaVersion: c.schemaVersion,
    messages: [...c.messages],
    signature: bytesToHex(c.signature),
    issuerPublicKey: bytesToHex(c.issuerPublicKey),
    claims: c.claims,
  };
}

export function deserializeCredential(s: SerializedCredential): Credential {
  return {
    schemaVersion: s.schemaVersion,
    messages: [...s.messages],
    signature: hexToBytes(s.signature),
    issuerPublicKey: hexToBytes(s.issuerPublicKey),
    claims: s.claims,
  };
}

export function serializeProof(p: Proof): SerializedProof {
  return {
    schemaVersion: p.schemaVersion,
    proof: bytesToHex(p.proof),
    disclosedIndexes: [...p.disclosedIndexes],
    disclosedMessages: [...p.disclosedMessages],
    totalMessages: p.totalMessages,
    binding: p.binding,
  };
}

export function deserializeProof(s: SerializedProof): Proof {
  return {
    schemaVersion: s.schemaVersion,
    proof: hexToBytes(s.proof),
    disclosedIndexes: [...s.disclosedIndexes],
    disclosedMessages: [...s.disclosedMessages],
    totalMessages: s.totalMessages,
    binding: s.binding,
  };
}

/** Convenience: the claim names a proof reveals, for logging/UI. */
export function disclosedClaimNames(proof: Proof): ClaimName[] {
  return proof.disclosedIndexes.map((i) => {
    const spec = CLAIM_SPEC_BY_INDEX[i];
    if (spec === undefined) throw new CredentialError(`index ${i} not in schema`);
    return spec.name;
  });
}

export { CLAIM_INDEX };
