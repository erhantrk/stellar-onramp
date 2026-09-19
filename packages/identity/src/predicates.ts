/**
 * Predicates — the surface a dApp actually calls.
 *
 * A predicate is nothing more than "reveal exactly these indices, and nothing else, and expect
 * exactly these values". Keeping that pairing in one object is what stops the two halves drifting:
 * a caller cannot disclose `over18` and then forget to check it is `true`, and cannot check a
 * claim it never asked to be disclosed.
 *
 * answers the question. `over18()` does not drag `over21` along; composing `over18 ∧ over21`
 * narrows the holder to an age band and is therefore an explicit, deliberate act by the caller.
 */

import {
  CLAIM_INDEX,
  ISSUER_JURISDICTION_POLICY,
  SCHEMA_VERSION,
  type ClaimName,
  type ClaimValue,
} from './schema.js';
import type { ProofBinding } from './binding.js';
import {
  derive,
  verifyDetailed,
  type Credential,
  type Proof,
  type VerifyOptions,
  type VerifyResult,
} from './credential.js';

/**
 * A disclosure request: which indices to reveal, and what the revealed values must equal.
 * `label` is for logs and consent UI only — it is not signed and carries no authority.
 */
export interface Predicate {
  readonly label: string;
  readonly disclose: readonly number[];
  readonly expect: Readonly<Partial<Record<ClaimName, ClaimValue>>>;
}

/** Holder is at least 18 by the issuer's determination at issuance time. */
export function over18(): Predicate {
  return {
    label: 'over18',
    disclose: [CLAIM_INDEX.over18],
    expect: { over18: true },
  };
}

/** Holder is at least 21. Separate index — disclosing both narrows the anonymity set. */
export function over21(): Predicate {
  return {
    label: 'over21',
    disclose: [CLAIM_INDEX.over21],
    expect: { over21: true },
  };
}

/** Holder is not on a sanctions list as of issuance. */
export function notSanctioned(): Predicate {
  return {
    label: 'notSanctioned',
    disclose: [CLAIM_INDEX.notSanctioned],
    expect: { notSanctioned: true },
  };
}

/** Holder is not a politically exposed person as of issuance. */
export function notPep(): Predicate {
  return {
    label: 'notPep',
    disclose: [CLAIM_INDEX.notPep],
    expect: { notPep: true },
  };
}

/** Liveness/biometric check passed during onboarding. */
export function livenessOk(): Predicate {
  return {
    label: 'livenessOk',
    disclose: [CLAIM_INDEX.livenessOk],
    expect: { livenessOk: true },
  };
}

export class PredicateError extends Error {
  override readonly name = 'PredicateError';
}

export interface CountryAllowedOptions {
  /**
   * The issuer's published jurisdiction set — the countries for which it sets
   * `jurisdictionOk = true`. Defaults to `ISSUER_JURISDICTION_POLICY`.
   */
  readonly issuerPolicy?: readonly string[];
}

/**
 * "The holder's country is in `allowed`."
 *
 * deliberately, because a disclosed country code is PII-adjacent and would shrink the anonymity
 * set hard. What the credential carries is the issuer's own boolean verdict, `jurisdictionOk`.
 *
 * So this predicate is satisfiable only when the relying party's allowlist is a SUPERSET of the
 * issuer's policy set: if every country the issuer would stamp `jurisdictionOk = true` for is
 * also acceptable to the relying party, then `jurisdictionOk = true` implies "country ∈ allowed".
 * If it is not a superset, no proof over schema v1 can answer the question and we throw rather
 * than return a predicate that is quietly weaker than it looks.
 *
 * A per-country answer needs a country attribute at a NEW appended index plus a schema-version
 * bump and full reissuance (§7.4 item 4). That is a product decision, not a code change.
 */
export function countryAllowed(
  allowed: readonly string[],
  options: CountryAllowedOptions = {},
): Predicate {
  const issuerPolicy = options.issuerPolicy ?? ISSUER_JURISDICTION_POLICY;
  const normalize = (list: readonly string[]): string[] => {
    const out = list.map((c) => {
      if (typeof c !== 'string' || !/^[A-Za-z]{2}$/.test(c)) {
        throw new PredicateError(`"${String(c)}" is not an ISO-3166-1 alpha-2 country code`);
      }
      return c.toUpperCase();
    });
    if (out.length === 0) throw new PredicateError('country allowlist must not be empty');
    return out;
  };

  const rp = new Set(normalize(allowed));
  const issuer = normalize([...issuerPolicy]);
  const missing = issuer.filter((c) => !rp.has(c));
  if (missing.length > 0) {
    throw new PredicateError(
      `countryAllowed is unsatisfiable over schema v1: the issuer stamps jurisdictionOk=true ` +
        `for ${missing.join(',')}, which your allowlist excludes. Schema v1 has no country ` +
        `attribute, so a per-country proof is impossible without a schema bump.`,
    );
  }

  return {
    label: `countryAllowed(${[...rp].sort().join(',')})`,
    disclose: [CLAIM_INDEX.jurisdictionOk],
    expect: { jurisdictionOk: true },
  };
}

/**
 * Conjunction. Merges the disclosure sets and the expectations; conflicting expectations for the
 * same claim are a programming error, not a silent last-write-wins.
 */
export function allOf(...predicates: readonly Predicate[]): Predicate {
  if (predicates.length === 0) throw new PredicateError('allOf requires at least one predicate');
  const disclose = new Set<number>();
  const expect: Partial<Record<ClaimName, ClaimValue>> = {};
  for (const p of predicates) {
    for (const idx of p.disclose) disclose.add(idx);
    for (const [name, value] of Object.entries(p.expect)) {
      const key = name as ClaimName;
      const existing = expect[key];
      if (existing !== undefined && existing !== value) {
        throw new PredicateError(
          `conflicting expectations for "${name}": ${String(existing)} vs ${String(value)}`,
        );
      }
      expect[key] = value as ClaimValue;
    }
  }
  return {
    label: predicates.map((p) => p.label).join(' AND '),
    disclose: [...disclose].sort((a, b) => a - b),
    expect,
  };
}

/**
 * The credential's own metadata block — indices 0..5, everything that is not a KYC verdict:
 * schemaVersion, issuerId, revocationIndex, issuedAt, expiresAt, subjectBinding.
 *
 * Disclosing these is what makes the OTHER half of the trust model executable. `over18=true`
 * alone is unbounded in time, unrevocable, unattached to a wallet and unattributed to an issuer —
 * a relying party holding only that has verified a signature, not a person. Concretely:
 *   index 0 -> the SIGNED schema version, so `verifyDetailed`'s cross-version check can bite at
 *              all (without it the version is only a self-asserted label on the presentation);
 *   index 1 -> the SIGNED issuer id, cross-checked against the verifying key, and the input a
 *              status-list resolver needs to know WHICH issuer's list to fetch;
 *   index 2 -> `VerifyOptions.statusList` (W3C Bitstring Status List revocation lookup);
 *   index 3 -> the issuedAt clock-skew sanity check;
 *   index 4 -> `VerifyOptions.currentTime`;
 *   index 5 -> `VerifyOptions.expectedSubjectBinding`.
 *
 * Widened from the previous {2,4,5}: index 3 costs nothing extra in privacy terms (issuedAt is
 * already implied by a disclosed expiresAt plus a published 90-day policy) and indices 0 and 1
 * are constants shared by every credential this issuer ever signed, so they narrow the anonymity
 * set by exactly zero while switching on two real checks.
 *
 * The one value expectation is `schemaVersion`, which IS a constant this module knows. Expiry is
 * compared against a clock and `revocationIndex` against a status list; neither is assertable here.
 */
export function credentialAudit(): Predicate {
  return {
    label: 'credentialAudit',
    disclose: [
      CLAIM_INDEX.schemaVersion,
      CLAIM_INDEX.issuerId,
      CLAIM_INDEX.revocationIndex,
      CLAIM_INDEX.issuedAt,
      CLAIM_INDEX.expiresAt,
      CLAIM_INDEX.subjectBinding,
    ],
    expect: { schemaVersion: SCHEMA_VERSION },
  };
}

/**
 * The bare gate booleans: adult and not sanctioned. Two disclosed booleans, ten hidden
 * attributes, U = 10 → proof = 144 + 32·14 = 592 bytes.
 *
 * on-ramp proof" disclosure set — that is {0,1,2,3,4,5,6,8} and it is what
 * `gateOnrampPredicate()` returns. This one answers "is the holder of SOME credential from this
 * issuer an unsanctioned adult" and nothing else. It hides `expiresAt`, so a credential that
 * lapsed years ago still verifies; it hides `revocationIndex`, so a revoked credential is
 * indistinguishable from a live one; it hides `subjectBinding`, so one KYC'd holder can gate an
 * unbounded number of wallets; and it hides `schemaVersion`, so the cross-version check in
 * `verifyDetailed` has nothing signed to bite on. Use it only where all four of those genuinely
 * do not matter. For an actual on-ramp gate use `gateOnrampPredicate()`.
 *
 * It is kept at {6,8} on purpose: it is the minimum-disclosure baseline, it is the shape the
 * frozen `standard-onramp` vector in fixtures/vectors.json pins, and that fixture is a wire
 * contract with the not-yet-written Rust verifier.
 */
export function standardOnrampPredicate(): Predicate {
  return allOf(over18(), notSanctioned());
}

/**
 * indices {0,1,2,3,4,5,6,8} — the full metadata block plus the two gate booleans.
 *
 * schema version is never on the table and `verifyDetailed`'s cross-version check cannot fire;
 * without index 1 there is no signed statement of WHICH issuer, which is also what
 * `kyc_gate.attest_bbs(..., issuer_id, revocation_index, expires_at)` must cross-check its
 * arguments against instead of trusting them. On-chain cost is unchanged: steps 5 and 6 of the
 * `attest_bbs` cost table sum to (2+R) + (2+U) = 4+N, invariant in how the split falls.
 *
 * Pair it with `{ currentLedger, currentTime, expectedSubjectBinding, statusList, replayGuard }`
 * on `checkPredicate` — disclosing the fields is necessary, but the checks are what make them
 * load-bearing, and `VerifyOptions` now forces you to name every one of them.
 */
export function gateOnrampPredicate(): Predicate {
  return allOf(credentialAudit(), over18(), notSanctioned());
}

/** Derive a proof that answers exactly `predicate` and nothing more. */
export async function prove(
  credential: Credential,
  predicate: Predicate,
  binding: ProofBinding,
): Promise<Proof> {
  return derive(credential, predicate.disclose, binding);
}

/**
 * Verify a proof against a predicate. Checks the cryptography, the binding, the expiry AND that
 * the disclosed index set is EXACTLY what the predicate asked for — a proof that reveals extra
 * attributes is rejected, because over-disclosure is a privacy failure even when it verifies.
 */
export async function checkPredicate(
  proof: Proof,
  predicate: Predicate,
  issuerPubKey: Uint8Array,
  expectedBinding: ProofBinding,
  options: Omit<VerifyOptions, 'expectedClaims' | 'expectedDisclosedIndexes'>,
): Promise<VerifyResult> {
  const want = [...predicate.disclose].sort((a, b) => a - b);
  const got = [...proof.disclosedIndexes];
  if (want.length !== got.length || want.some((v, i) => v !== got[i])) {
    return {
      valid: false,
      reason: 'disclosure-shape',
      detail: `predicate "${predicate.label}" wants indexes [${want.join(',')}], ` +
        `proof discloses [${got.join(',')}]`,
    };
  }
  // BOTH halves of the predicate are forwarded, and NEITHER is the caller's to supply — that is
  // the whole reason this function exists. `expectedDisclosedIndexes` is redundant with the check
  // just above (which stays, because its message names the predicate and an operator triaging by
  // `detail` needs that), but passing it means there is no arrangement of arguments in which
  // `checkPredicate` reaches `verifyDetailed` with the disclosure-set check switched off.
  return verifyDetailed(proof, issuerPubKey, expectedBinding, {
    ...options,
    expectedClaims: predicate.expect,
    expectedDisclosedIndexes: want,
  });
}
