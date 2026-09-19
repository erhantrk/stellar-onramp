/**
 * The status list PUBLISHER. The gateway is its natural home: it is the BBS+ issuer, it allocates the
 * revocation indexes, and it is the only party that knows which of them are revoked.
 *
 * is here; serving it over HTTP is the cut transport layer.
 *
 * THE PUBLISHER MUST EMIT A LIST ITS OWN DECODER ACCEPTS, and identity's decoder is strict in four
 * ways that a naive publisher gets wrong. All four are handled by delegating the bitstring entirely to
 * identity's `encodeStatusList`, which is the same code path `decodeStatusList` inverts:
 *
 *   1. A SHORT LIST IS REJECTED, NOT PADDED. `MINIMUM_STATUS_LIST_ENTRIES` is 131,072 and it is a
 *      PRIVACY floor, not a formatting nit — with a hundred-entry list, "the credential at index 42 of
 *      this list" is close to a name. Padding a short list would manufacture the anonymity set the
 *      issuer failed to provide.
 *   2. AN UNKNOWN `statusPurpose` IS REJECTED, NOT READ AS "NOT REVOKED".
 *   3. `statusMessage` IS ENFORCED per W3C §2.2 whenever `statusSize > 1`.
 *   4. GZIP GOES THROUGH THE WHATWG `DecompressionStream`, and the pipeline order is
 *      gzip -> base64url -> multibase, so the encoder must compress FIRST.
 *
 * Reimplementing any of that here would be the encoder/decoder disagreement the whole module exists to
 * prevent, so none of it is reimplemented.
 */

import { encodeStatusList } from '@stellaronramp/identity';
import type { StatusPurpose } from '@stellaronramp/identity';

import {
  BITSTRING_STATUS_LIST_CREDENTIAL_TYPE,
  BITSTRING_STATUS_LIST_TYPE,
  STATUS_LIST_CRYPTOSUITE,
  StatusCredentialError,
  VC_V2_CONTEXT,
  signStatusListCredential,
  toXsdDateTime,
} from './credential.js';
import type { StatusListCredentialDocument } from './credential.js';

/**
 * How long a published list claims to be valid, in seconds. 24 hours.
 *
 * This is the ISSUER's bound and it is deliberately short. The list is the ONLY revocation channel for
 * the off-chain credential (the on-chain `revocation_epoch` is the other channel, and it covers the
 * attestation, not the credential), so `validUntil` is an upper bound on how long a stale mirror can
 * be believed. A one-week `validUntil` means a caller who caches to `validUntil` has a week-long
 *
 * BOTH DIRECTIONS HURT. Too long and a revocation takes that long to become universally visible. Too
 * short and every verifier re-fetches constantly, the publisher becomes a hot path, and an outage of
 * the publisher fails every verification CLOSED — which is correct and is also a total outage. 24 h at
 * the envelope with a much shorter verifier-side freshness bound (see resolver.ts's
 * `DEFAULT_STATUS_LIST_MAX_AGE_SECONDS`, 300 s) is the shape that lets the verifier be stricter than
 * the issuer without the issuer having to republish every five minutes.
 */
export const DEFAULT_STATUS_LIST_VALIDITY_SECONDS = 24 * 60 * 60;

export interface PublishStatusListRequest {
  /** Stable list URL. Becomes `id`; `credentialSubject.id` is this plus `#list`. */
  readonly url: string;
  /** The issuer identifier the verifier pins. Our convention: identity's 32-byte hex `issuerId`. */
  readonly issuer: string;
  /** Which key signed. A label only; the verifier never dereferences it. */
  readonly verificationMethod: string;
  readonly statusPurpose: StatusPurpose;
  /** Indices whose bit is set (revoked / suspended). */
  readonly revoked: readonly number[];
  /** Entry count. Defaults to identity's spec minimum; may not be below it. */
  readonly entries?: number;
  readonly statusSize?: number;
  /** Unix seconds. */
  readonly validFromSeconds: number;
  /** Unix seconds. Defaults to `validFromSeconds + DEFAULT_STATUS_LIST_VALIDITY_SECONDS`. */
  readonly validUntilSeconds?: number;
  /** 32-byte Ed25519 seed, or a PKCS#8 DER private key. */
  readonly signingKey: { readonly seed?: Uint8Array; readonly pkcs8Der?: Uint8Array };
}

/**
 * Build and sign a `BitstringStatusListCredential`.
 *
 * HTTPS IS ENFORCED ON THE PUBLISHED `id` TOO, not just on the fetch. The `id` is what a credential's
 * `credentialStatus.statusListCredential` points at, so an `http:` id would be baked into every
 * that name a plaintext URL. Catching it at publish time is the only place it is cheap.
 */
export async function publishStatusList(
  request: PublishStatusListRequest,
): Promise<StatusListCredentialDocument> {
  assertHttpsUrl(request.url);
  if (typeof request.issuer !== 'string' || request.issuer.length === 0) {
    throw new StatusCredentialError('refusing to publish a status list with no issuer');
  }
  if (typeof request.verificationMethod !== 'string' || request.verificationMethod.length === 0) {
    throw new StatusCredentialError(
      'refusing to publish a status list with no verificationMethod; a verifier pinned to a key ' +
        'label cannot check the label it was given',
    );
  }
  const validFrom = request.validFromSeconds;
  const validUntil = request.validUntilSeconds ?? validFrom + DEFAULT_STATUS_LIST_VALIDITY_SECONDS;
  if (!Number.isInteger(validFrom) || validFrom < 0) {
    throw new StatusCredentialError(
      `refusing to publish a status list with validFrom ${String(validFrom)}`,
    );
  }
  if (!Number.isInteger(validUntil) || validUntil <= validFrom) {
    throw new StatusCredentialError(
      `refusing to publish a status list whose validUntil (${String(validUntil)}) is not strictly ` +
        `after its validFrom (${validFrom}); a zero-length or inverted validity window is a list ` +
        'that is expired the instant it is served, which fails every verification CLOSED',
    );
  }
  for (const index of request.revoked) {
    if (!Number.isInteger(index) || index < 0) {
      throw new StatusCredentialError(
        `refusing to publish a status list with revoked index ${String(index)}; a non-integer or ` +
          'negative index would silently set no bit at all, i.e. would fail to revoke someone',
      );
    }
  }

  // identity owns the bitstring, the gzip, the base64url, the multibase prefix, the 131,072-entry
  // floor, the statusPurpose allowlist and the statusMessage rule. Anything it rejects, it rejects
  // here, at publish time, rather than at every verifier.
  const list = await encodeStatusList({
    statusPurpose: request.statusPurpose,
    set: request.revoked,
    ...(request.entries === undefined ? {} : { entries: request.entries }),
    ...(request.statusSize === undefined ? {} : { statusSize: request.statusSize }),
  });

  const subject: StatusListCredentialDocument['credentialSubject'] = {
    id: `${request.url}#list`,
    type: BITSTRING_STATUS_LIST_TYPE,
    statusPurpose: list.statusPurpose,
    encodedList: list.encodedList,
    ...(list.statusSize === undefined ? {} : { statusSize: list.statusSize }),
    ...(list.statusMessage === undefined ? {} : { statusMessage: list.statusMessage }),
  };

  const unsigned: StatusListCredentialDocument = {
    '@context': [VC_V2_CONTEXT],
    id: request.url,
    type: ['VerifiableCredential', BITSTRING_STATUS_LIST_CREDENTIAL_TYPE],
    issuer: request.issuer,
    validFrom: toXsdDateTime(validFrom),
    validUntil: toXsdDateTime(validUntil),
    credentialSubject: subject,
  };

  return signStatusListCredential(unsigned, request.signingKey, {
    type: 'DataIntegrityProof',
    cryptosuite: STATUS_LIST_CRYPTOSUITE,
    created: toXsdDateTime(validFrom),
    verificationMethod: request.verificationMethod,
    proofPurpose: 'assertionMethod',
  });
}

/**
 * HTTPS-only URL check, shared with the resolver.
 *
 * `new URL()` and not a regex — but NOT because `URL` rejects more strings. It does not. Both
 * `https://evil.com\@good.com` and `https:/\/\evil.com` PARSE, and WHATWG normalisation resolves
 * both to `hostname === 'evil.com'` (measured, `node -e "new URL(...)"`). What `URL` buys is that
 * the TWO checks below run against the WHATWG-authoritative parse of the authority instead of a
 * regex's guess at it: a regex written to "find the host" reads `good.com` out of the first string
 * and something host-shaped out of the second, while `url.protocol` and `url.username`/
 * `url.password` are the values a fetch would actually use. The parser is a decoder, not a filter;
 * the filtering is done by the explicit checks.
 *
 * The protocol is compared to the exact string `'https:'` — `URL` normalises the scheme to
 * lowercase, so `HTTPS://` is fine and `httpss:` is not.
 *
 * `url.hostname` IS PARSED AND DELIBERATELY NOT CHECKED — spelled out because an earlier version
 * enumeration-that-reads-as-coverage defect the comment was rewritten to remove. The host is what
 * the normalisation above is *for*: it is decoded correctly so that a caller which does have a
 * host policy applies it to the right string.
 *
 * NOTE what this therefore does NOT do: it does not constrain WHICH https host is named. An
 * attacker-supplied `https://evil.com/list.json` is accepted here and rejected, if at all, by the
 * caller's own issuer/host policy.
 *
 * REFUSED: `http:`, `file:`, `data:`, `blob:`, `ftp:`, a protocol-relative `//host` (which `new URL()`
 * rejects outright without a base, and that rejection is the correct behaviour — it is not a URL), and
 * any URL carrying credentials in the authority (`https://user:pass@host`), because those are
 * invisible in a log line and are a classic way to make a URL point somewhere unexpected.
 */
export function assertHttpsUrl(raw: unknown, what = 'status list URL'): URL {
  if (typeof raw !== 'string' || raw.length === 0) {
    throw new StatusCredentialError(`refusing a ${what} that is not a non-empty string`);
  }
  let url: URL;
  try {
    url = new URL(raw);
  } catch (cause) {
    throw new StatusCredentialError(
      `refusing a ${what} that is not an absolute URL: "${raw.slice(0, 96)}". A protocol-relative ` +
        '"//host/path" is deliberately refused here rather than resolved against a base — resolving ' +
        'it would inherit whatever scheme the caller happened to be on.',
      { cause },
    );
  }
  if (url.protocol !== 'https:') {
    throw new StatusCredentialError(
      `refusing a ${what} with scheme "${url.protocol}"; HTTPS ONLY. Over plain HTTP an on-path ` +
        'attacker can serve an all-zero bitstring and UN-REVOKE EVERY HOLDER (the status-list design note). ' +
        'file:, data: and blob: are refused for the same reason plus local-file disclosure.',
    );
  }
  if (url.username !== '' || url.password !== '') {
    throw new StatusCredentialError(
      `refusing a ${what} that embeds credentials in its authority; "https://a@b/" points at b, not ` +
        'a, and that is invisible at a glance in a log line',
    );
  }
  return url;
}
