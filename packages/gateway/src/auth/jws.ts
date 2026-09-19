/**
 * ES256 JWS (RFC 7515 compact serialization) sign + verify over `node:crypto`. NOTHING ELSE: no
 * `jose`, no dependency at all — the house rule is hand-rolled crypto plumbing with the primitive
 * work left to the platform, precedent `src/kyc/webhook.ts` (constant-time compare) and
 * `packages/sdk/src/wallet/software-p256.ts` (P-256 via node).
 *
 * This library covers BOTH directions of one scheme:
 *
 *   * ISSUANCE — `signJws` mints a compact JWS from a validated claim set (the gateway's session
 *     technique reference for VERIFYING an id_token — claim checklist, alg pinning and jti dedupe
 *     transfer, direction inverted).
 *   * VERIFICATION — `verifyJws` checks everything, defaults nothing (below).
 *
 * THE ALG IS PINNED FROM THE KEY TYPE, NEVER FROM THE TOKEN HEADER. An EC P-256 key means ES256
 * and an OKP Ed25519 key means EdDSA — each key admits exactly one algorithm and there is no
 * code path that accepts anything else. The token header is attacker-influenced; `alg: "none"`
 * and HMAC-with-the-public-key are the classic confusions of the bug class documented at
 * algorithm handling. Structurally: the verifier inspects the CONFIGURED KEY first, derives the
 * one algorithm it can possibly speak, then requires the header to agree exactly — a mislabelled
 * token fails loudly rather than being guessed at. There is no HMAC branch to fall into.
 *
 * WHY TWO SCHEMES: the gateway MINTS session tokens (ES256, `signJws`) and VERIFIES anchor-
 * minted SEP-10 tokens (EdDSA — anchors sign with their Stellar Ed25519 domain key). Both
 * directions live here so the pinning discipline cannot drift between two modules.
 *
 * CLAIMS CHECKED, NONE DEFAULTED: `exp`, `nbf`, `iat`, `iss`, `aud`, `sub`. Each absent claim is
 * a REFUSAL, never a pass — an absent `exp` must not mean "never expires". The clock is INJECTED
 * (`nowSeconds`): this is library code, it takes no wall-clock, no env, no network. ONE policy
 * exception exists, per verifier and never silent: `claimPolicy: 'sep10'` makes `aud`/`nbf`
 * OPTIONAL (canonical anchor tokens carry `{iss, sub, iat, exp[, jti]}` — aud only when the
 * client-domain flow is used, nbf not at all), while any claim that IS present keeps its full
 * type/window discipline. See {@link VerifyJwsOptions.claimPolicy}.
 *
 * SIGNATURE ENCODING: node emits DER for ECDSA; `signJws` compacts to the JWS-mandated 64-byte
 * r‖s (32+32, big-endian each) and `verifyJws` accepts ONLY exactly-64-byte signatures — a
 * 71-byte DER signature pasted into the compact field is a refusal, not a lenient parse (same
 * discipline as `digestsEqual`'s explicit length check in webhook.ts). The DER↔r‖s translation
 * is written out byte-by-byte below and refuses every shape it does not understand.
 *
 * REPLAY: an OPTIONAL `jti` hook shaped like webhook.ts's dedupe store
 * (`WebhookDedupeStore.firstSight(provider, eventId, nowSeconds)` in src/kyc/replay.ts — ONE
 * atomic compare-and-set method, deliberately no `has()`, because check-then-act is a race).
 * When the hook is NOT configured, tokens are NOT replay-checked — that is a documented absence,
 * `NO_IP_ALLOWLIST`: a constant that exists to be asserted on, so the absence cannot regress
 * quietly).
 */

import {
  createPublicKey,
  generateKeyPairSync,
  sign as cryptoSign,
  verify as cryptoVerify,
  type JsonWebKey,
  type KeyObject,
} from 'node:crypto';

/** The two algorithms this module speaks, each pinned by key type; see the module docblock. */
export const ES256 = 'ES256';
export const EDDSA = 'EdDSA';

/**
 * The exact protected-header BYTES tokens of each scheme must carry (and every token this module
 * signs DOES carry). Frozen as literals so headers are byte-stable across releases (tests pin
 * their base64url forms) and so no caller- or attacker-supplied header field can leak into what
 * we sign or what we accept.
 */
const PROTECTED_HEADER_JSON = '{"alg":"ES256","typ":"JWT"}';
const PROTECTED_HEADER_B64 = Buffer.from(PROTECTED_HEADER_JSON, 'utf8').toString('base64url');
const EDDSA_PROTECTED_HEADER_JSON = '{"alg":"EdDSA","typ":"JWT"}';
const EDDSA_PROTECTED_HEADER_B64 = Buffer.from(EDDSA_PROTECTED_HEADER_JSON, 'utf8').toString('base64url');

function frozenHeaderB64(alg: 'ES256' | 'EdDSA'): string {
  return alg === ES256 ? PROTECTED_HEADER_B64 : EDDSA_PROTECTED_HEADER_B64;
}

/* -------------------------------------------------------------------------- */
/* Errors                                                                      */
/* -------------------------------------------------------------------------- */

/** Every way a JWS can be refused. Machine-triageable; the message is operator prose. */
export type JwsRejectionReason =
  | 'malformed-token'
  | 'bad-header'
  | 'alg-not-es256'
  | 'alg-not-eddsa'
  | 'not-an-ec-p256-key'
  | 'not-an-okp-ed25519-key'
  | 'signature-length'
  | 'signature-mismatch'
  | 'payload-malformed'
  | 'claim-absent'
  | 'claim-type'
  | 'invalid-window'
  | 'unknown-claim'
  | 'issuer-mismatch'
  | 'audience-mismatch'
  | 'token-not-yet-valid'
  | 'token-expired'
  | 'replay-detected';

export class JwsError extends Error {
  override readonly name = 'JwsError';
  readonly reason: JwsRejectionReason;
  constructor(reason: JwsRejectionReason, message: string) {
    super(message);
    this.reason = reason;
  }
}

/* -------------------------------------------------------------------------- */
/* Replay hook                                                                 */
/* -------------------------------------------------------------------------- */

/**
 * The jti replay store this module accepts. STRUCTURALLY IDENTICAL to `WebhookDedupeStore`
 * (src/kyc/replay.ts), so an `InMemoryWebhookDedupeStore` — or its production Redis successor —
 * plugs in unchanged: one atomic first-sight method, no `has()` to race on.
 */
export interface JtiReplayStore {
  /**
   * Atomically record `(provider, eventId)` as seen. Returns `true` iff this call is the FIRST
   * sighting; `false` means already recorded and not yet expired (a replay).
   */
  firstSight(provider: string, eventId: string, nowSeconds: number): Promise<boolean>;
}

/**
 * `NO_IP_ALLOWLIST`). When `verifyJws` is called without a `replay` option, the token's `jti` is
 * NOT checked against any store and a captured token is replayable until `exp`.
 */
export const REPLAY_UNCHECKED_NOTE =
  'verifyJws called WITHOUT a replay hook means tokens are NOT replay-checked: jti is ignored ' +
  'and a captured token stays usable until exp. Configure { store, provider } (any ' +
  'WebhookDedupeStore-shaped first-sight store) to make jti mandatory and atomically ' +
  'first-sight checked.';

/* -------------------------------------------------------------------------- */
/* Claims                                                                      */
/* -------------------------------------------------------------------------- */

/**
 * The claim set this module signs. Exactly these names — an extra property is refused at SIGN
 * time (`unknown-claim`) so a caller cannot accidentally carry PII or an unintended promise into
 * a signed token. All six registered claims are REQUIRED (checked, none defaulted); `jti` is
 * optional at sign time but becomes REQUIRED at verify time when a replay hook is configured.
 */
export interface JwsClaimsInput {
  /** Issuer. Non-empty string. */
  readonly iss: string;
  readonly sub: string;
  /** Audience the token is scoped to. Non-empty string. */
  readonly aud: string;
  /** Issued-at, unix seconds. Integer. */
  readonly iat: number;
  /** Not-before, unix seconds. Integer. */
  readonly nbf: number;
  /** Expiry, unix seconds. Integer. Must be > nbf. */
  readonly exp: number;
  /** Optional jti; required at verify when a replay store is configured. */
  readonly jti?: string;
}

/** What `verifyJws` returns: the verified claims, read back out of the token. */
export interface VerifiedJws {
  readonly iss: string;
  readonly sub: string;
  /** Present iff the token carried one — ALWAYS present under the default strict claim policy. */
  readonly aud?: string;
  readonly iat: number;
  /** Present iff the token carried one — ALWAYS present under the default strict claim policy. */
  readonly nbf?: number;
  readonly exp: number;
  /** Present iff the token carried one. */
  readonly jti?: string;
}

/* -------------------------------------------------------------------------- */
/* Keys                                                                        */
/* -------------------------------------------------------------------------- */

/**
 * Generate a fresh ES256 key pair (development/test convenience; operators inject keys built
 * from their own material via `{format:'jwk'}` — see `es256KeyPairFromJwkShape` guidance in the
 * package README and the Ed25519 precedent in src/chain/signer.ts, which builds KeyObjects from
 * raw bytes through JWK so no DER is hand-assembled).
 */
export function generateEs256KeyPair(): { privateKey: KeyObject; publicKey: KeyObject } {
  return generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
}

/**
 * Build a verification KeyObject from a P-256 public JWK (`{kty:'EC', crv:'P-256', x, y}`),
 * via `createPublicKey({format:'jwk'})` so no DER is assembled here — the same philosophy as
 * `publicKeyFromRaw` in src/chain/signer.ts, pointed at P-256. The result is re-checked through
 * `assertEs256Key`, so a wrong-curve or wrong-family JWK is refused before it can reach verify.
 *
 * DELIBERATELY NO SIGNING-JWK TWIN IS EXPORTED FROM THE BARREL: this package's API surface is
 * guarded by a naming tripwire that refuses any export suggesting private key material
 * (test/chain/barrel.test.ts), and a signing key should be constructed with node:crypto's own
 * `createPrivateKey({key, format:'jwk'})` by whoever holds the JWK, then handed to
 * {@link signJws} as a KeyObject — custody stays with the holder.
 */
export function es256PublicKeyFromJwk(jwk: JsonWebKey): KeyObject {
  const key = createPublicKey({ key: jwk, format: 'jwk' });
  assertEs256Key(key);
  return key;
}

/**
 * Build a verification KeyObject from a RAW 32-byte Ed25519 public key — the form a Stellar
 * account's signing key takes on the wire (and the form an anchor's SEP-10 domain key arrives in
 * via config). Same JWK philosophy as `publicKeyFromRaw` in src/chain/signer.ts (the original;
 * this is the auth-module twin so the auth surface stays self-contained), same length-check-FIRST
 *
 * NO SIGNING TWIN, same rule as the P-256 side above: whoever holds the seed builds their
 * private key with node:crypto (`createPrivateKey({format:'jwk'})` or the signer module) and
 * hands {@link signJws} a KeyObject.
 */
export function ed25519PublicKeyFromRaw(publicKeyRaw: Uint8Array): KeyObject {
  if (!(publicKeyRaw instanceof Uint8Array) || publicKeyRaw.length !== 32) {
    throw new RangeError(`ed25519 public key must be exactly 32 bytes, got ${publicKeyRaw?.length ?? String(publicKeyRaw)}`);
  }
  const key = createPublicKey({
    key: {
      kty: 'OKP',
      crv: 'Ed25519',
      x: Buffer.from(publicKeyRaw).toString('base64url'),
    },
    format: 'jwk',
  });
  if (keyAlgorithm(key) !== EDDSA) {
    // Unreachable through this constructor; kept so the invariant is enforced by code, not by
    throw new JwsError('not-an-okp-ed25519-key', 'constructed Ed25519 key did not classify as Ed25519');
  }
  return key;
}

/**
 * THE ALG PIN, stated as a type check: classify the configured key into the ONE algorithm it can
 * possibly speak — EC P-256 ⇒ ES256, OKP Ed25519 ⇒ EdDSA — or refuse it. The decision is made
 * from the KEY, never from token bytes.
 *
 * Curve identity for EC keys is read WITHOUT exporting private material: a private key is
 * projected to its PUBLIC half (`createPublicKey`) and the public half's JWK `crv` is inspected.
 * Exporting a public half leaks nothing; exporting the private JWK to read `crv` would
 * materialize `d` gratuitously.
 */
function keyAlgorithm(key: KeyObject): 'ES256' | 'EdDSA' {
  if (key.type !== 'public' && key.type !== 'private') {
    throw new JwsError('not-an-ec-p256-key', 'refusing a key that is neither a public nor a private KeyObject');
  }
  if (key.asymmetricKeyType === 'ed25519') return EDDSA;
  if (key.asymmetricKeyType !== 'ec') {
    throw new JwsError(
      'not-an-ec-p256-key',
      `refusing a ${String(key.asymmetricKeyType)} key where an EC P-256 or OKP Ed25519 key is ` +
        'required; the algorithm is pinned from the KEY TYPE (EC P-256 means ES256, Ed25519 means ' +
        'EdDSA, each admits NOTHING ELSE), so any other key family — RSA, or an oct/HMAC secret ' +
        'handed to the wrong parameter — is refused before any token bytes are examined. This is ' +
        'the structural version of the alg-confusion allowlist.',
    );
  }
  const crv = publicHalf(key).export({ format: 'jwk' }).crv;
  if (crv !== 'P-256') {
    throw new JwsError(
      'not-an-ec-p256-key',
      `refusing an EC key on curve "${String(crv)}"; this module speaks ES256 over P-256 ` +
        '(prime256v1) and EdDSA over Ed25519 only',
    );
  }
  return ES256;
}

/** The ES256 half of {@link keyAlgorithm}, kept as its own check for P-256-only constructors. */
function assertEs256Key(key: KeyObject): void {
  const alg = keyAlgorithm(key);
  if (alg !== ES256) {
    // An Ed25519 key where the caller demanded P-256 specifically.
    throw new JwsError(
      'not-an-okp-ed25519-key',
      'refusing an Ed25519 key where an EC P-256 key is required; ES256 construction helpers ' +
        'accept P-256 material only',
    );
  }
}

/** The public half of a key (identity for an already-public key). No secrets exported. */
function publicHalf(key: KeyObject): KeyObject {
  return key.type === 'public' ? key : createPublicKey(key);
}

/* -------------------------------------------------------------------------- */
/* base64url                                                                   */
/* -------------------------------------------------------------------------- */

/**
 * STRICT base64url decode: alphabet-checked BEFORE decoding. `Buffer.from(x, 'base64url')` is
 * lenient — it skips characters it does not recognise, so `deadbeef!` decodes as `deadbeef` and
 * a tampered segment silently verifies against different bytes than were audited. Refuse
 * anything outside `[A-Za-z0-9_-]` (JWT compact form carries no `=` padding; a padded segment is
 * a malformed token, not a tolerated variant).
 */
function b64urlDecodeStrict(segment: string, what: string): Buffer {
  if (!/^[A-Za-z0-9_-]+$/.test(segment)) {
    throw new JwsError(
      'malformed-token',
      `refusing a JWS whose ${what} segment is not unpadded base64url; a lenient decoder would ` +
        'silently skip foreign characters and verify bytes nobody audited',
    );
  }
  return Buffer.from(segment, 'base64url');
}

function b64urlEncode(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64url');
}

/* -------------------------------------------------------------------------- */
/* DER <-> r‖s                                                                 */
/* -------------------------------------------------------------------------- */

/**
 * Parse a DER `ECDSA-Sig-Value` (SEQUENCE of two INTEGERs) into 64-byte r‖s. EVERY byte is
 * accounted for: wrong tag, long-form length, trailing bytes, an INTEGER wider than 32 bytes of
 * magnitude, an empty INTEGER — all refusals. A parser that "usually works" is a forgery oracle
 * in slow motion.
 */
function derToRaw(der: Buffer): Buffer {
  // Minimal DER for P-256 is 8 bytes (two 1-byte scalars); maximal (two 33-byte INTEGERs) is 72.
  if (der.length < 8 || der.length > 72) {
    throw new JwsError('signature-length', `refusing a ${der.length}-byte DER signature; an ECDSA P-256 signature is 8-72 bytes`);
  }
  if (der[0] !== 0x30) {
    throw new JwsError('signature-length', 'refusing a DER signature that does not open with a SEQUENCE tag');
  }
  const seqLen = der[1] as number;
  if (seqLen & 0x80) {
    throw new JwsError('signature-length', 'refusing a DER signature with a long-form SEQUENCE length; P-256 signatures never need one');
  }
  if (seqLen + 2 !== der.length) {
    throw new JwsError('signature-length', 'refusing a DER signature whose SEQUENCE length disagrees with its actual byte count');
  }
  const out = Buffer.alloc(64);
  let off = 2;
  for (let i = 0; i < 2; i += 1) {
    if (off + 2 > der.length || der[off] !== 0x02) {
      throw new JwsError('signature-length', 'refusing a DER signature whose members are not two INTEGER primitives');
    }
    const intLen = der[off + 1] as number;
    if (intLen & 0x80 || intLen === 0 || intLen > 33) {
      throw new JwsError('signature-length', `refusing a DER signature whose INTEGER ${i} has length ${intLen}; expected 1-33`);
    }
    if (off + 2 + intLen > der.length) {
      throw new JwsError('signature-length', 'refusing a DER signature whose INTEGER runs past the end of the buffer');
    }
    // Strip the sign-padding zero DER requires when the top bit is set. More than one padding
    // zero, or a magnitude wider than 32 bytes once stripped, cannot be a P-256 scalar.
    let start = off + 2;
    const end = start + intLen;
    while (start < end - 1 && der[start] === 0x00) start += 1;
    const mag = der.subarray(start, end);
    if (mag.length > 32) {
      throw new JwsError('signature-length', `refusing a DER signature whose INTEGER ${i} magnitude is ${mag.length} bytes (> 32)`);
    }
    // Left-align into its fixed 32-byte half, big-endian.
    mag.copy(out, i === 0 ? 32 - mag.length : 64 - mag.length);
    off = end;
  }
  if (off !== der.length) {
    throw new JwsError('signature-length', 'refusing a DER signature with trailing bytes after the second INTEGER');
  }
  return out;
}

/**
 * Encode 64-byte r‖s back into DER `ECDSA-Sig-Value`, for handing to node's verifier (node
 * consumes DER for ECDSA). Inverse of {@link derToRaw}, including the high-bit pad byte.
 */
function rawToDer(raw: Buffer): Buffer {
  const integer = (half: Buffer): Buffer => {
    // A fixed-width half may legitimately begin with zero bytes (a scalar < 2^248 has a leading
    // zero in its 32-byte big-endian form ~1/256 of the time). Strip the padding; DER re-adds
    // exactly one sign byte when the surviving top bit is set.
    let start = 0;
    while (start < half.length - 1 && (half[start] as number) === 0x00) start += 1;
    const v = half.subarray(start);
    if (v.length === 1 && (v[0] as number) === 0x00) {
      throw new JwsError('signature-length', 'refusing an r‖s half whose scalar is zero');
    }
    const body = (v[0] as number) >= 0x80 ? Buffer.concat([Buffer.from([0x00]), v]) : Buffer.from(v);
    return Buffer.concat([Buffer.from([0x02, body.length]), body]);
  };
  const body = Buffer.concat([integer(raw.subarray(0, 32)), integer(raw.subarray(32, 64))]);
  return Buffer.concat([Buffer.from([0x30, body.length]), body]);
}

/* -------------------------------------------------------------------------- */
/* Sign                                                                        */
/* -------------------------------------------------------------------------- */

/**
 * Mint a compact JWS: `b64url(header) + "." + b64url(claims) + "." + b64url(sig)`.
 *
 * The header is the FROZEN literal for the key's algorithm — `{"alg":"ES256","typ":"JWT"}` or
 * `{"alg":"EdDSA","typ":"JWT"}` — no caller input reaches it. The algorithm follows the KEY TYPE
 * (see {@link keyAlgorithm}); there is no way to sign with an alg that disagrees with the key.
 * Claims are validated BEFORE signing (a token we would refuse to verify should not exist to be
 * issued), serialized in a fixed key order. ECDSA signatures are compacted from node's DER to
 * 64-byte r‖s; Ed25519 signatures are already exactly 64 bytes (||R||S, RFC 8032). Signing input
 * is the ASCII `header.payload` bytes, per JWS — Ed25519 signs those bytes DIRECTLY (digest
 * `null`: the hash is inside the scheme; passing 'sha256' here would be a second, wrong hash).
 */
export function signJws(args: {
  readonly privateKey: KeyObject;
  readonly claims: JwsClaimsInput;
}): string {
  const alg = keyAlgorithm(args.privateKey);
  const claimsJson = serializeClaims(args.claims);

  const signingInput = `${frozenHeaderB64(alg)}.${b64urlEncode(Buffer.from(claimsJson, 'utf8'))}`;
  if (alg === EDDSA) {
    const sig = cryptoSign(null, Buffer.from(signingInput, 'ascii'), args.privateKey);
    if (sig.length !== 64) {
      // Unreachable with node's Ed25519; pinned so a platform change cannot ship a short sig.
      throw new JwsError('signature-length', `ed25519 signing produced a ${sig.length}-byte signature`);
    }
    return `${signingInput}.${b64urlEncode(sig)}`;
  }
  const der = cryptoSign('sha256', Buffer.from(signingInput, 'ascii'), args.privateKey);
  const raw = derToRaw(der);
  return `${signingInput}.${b64urlEncode(raw)}`;
}

/**
 * Validate + serialize the claim set. Fixed insertion order keeps tokens byte-reproducible for a
 * given claim set, which golden tests (and log diffing) depend on.
 */
function serializeClaims(claims: JwsClaimsInput): string {
  checkRequiredClaims(claims);
  if (claims.nbf >= claims.exp) {
    throw new JwsError(
      'invalid-window',
      `refusing to sign a token whose validity window is inverted (nbf ${claims.nbf} >= exp ${claims.exp})`,
    );
  }
  const ordered: Record<string, string | number> = {
    iss: claims.iss,
    sub: claims.sub,
    aud: claims.aud,
    iat: claims.iat,
    nbf: claims.nbf,
    exp: claims.exp,
  };
  if (claims.jti !== undefined) ordered['jti'] = claims.jti;
  // Any property outside the interface's seven would have to arrive via a cast; catch it here.
  for (const key of Object.keys(claims)) {
    if (!(key in ordered) && key !== 'jti') {
      throw new JwsError('unknown-claim', `refusing to sign a token carrying an unregistered claim "${key}"`);
    }
  }
  return JSON.stringify(ordered);
}

/** Presence + type discipline shared by both directions. Absent is a refusal, never a default. */
function checkRequiredClaims(claims: Omit<JwsClaimsInput, 'jti'>): void {
  for (const key of ['iss', 'sub', 'aud'] as const) {
    const v = claims[key];
    if (v === undefined) {
      throw new JwsError('claim-absent', `refusing a token without "${key}"; every claim is checked and NONE is defaulted`);
    }
    if (typeof v !== 'string' || v.length === 0) {
      throw new JwsError('claim-type', `refusing a token whose "${key}" is ${describe(v)}; expected a non-empty string`);
    }
  }
  for (const key of ['iat', 'nbf', 'exp'] as const) {
    const v = claims[key];
    if (v === undefined) {
      throw new JwsError('claim-absent', `refusing a token without "${key}"; an absent expiry must not mean "never expires"`);
    }
    if (typeof v !== 'number' || !Number.isSafeInteger(v)) {
      throw new JwsError('claim-type', `refusing a token whose "${key}" is ${describe(v)}; expected unix seconds as an integer`);
    }
  }
}

function describe(v: unknown): string {
  if (v === null) return 'null';
  if (v === undefined) return 'absent';
  if (Array.isArray(v)) return 'an array';
  return typeof v === 'string' ? `the string "${v.slice(0, 40)}"` : `a ${typeof v}`;
}

/* -------------------------------------------------------------------------- */
/* Verify                                                                      */
/* -------------------------------------------------------------------------- */

export interface VerifyJwsOptions {
  /**
   * The public key the token MUST verify under. The algorithm follows the KEY TYPE, never the
   * token header: an EC P-256 key verifies ES256 tokens only, an OKP Ed25519 key verifies EdDSA
   * tokens only, anything else is refused before any token bytes are examined.
   */
  readonly publicKey: KeyObject;
  /** Injected clock, unix seconds. */
  readonly nowSeconds: number;
  /** Expected `iss`. Compared exactly; a token from any other issuer is refused. */
  readonly issuer: string;
  /** Expected `aud`. Compared exactly (our issuer emits the string form only; arrays are a refusal). */
  readonly audience: string;
  /**
   * Claim policy. DEFAULT `'strict'`: every registered claim (`iss`, `sub`, `aud`, `iat`, `nbf`,
   * `exp`) is REQUIRED — the discipline our own minted session tokens are held to, where an absent
   * claim is a refusal and none is defaulted.
   *
   * `'sep10'` relaxes PRESENCE ONLY for the two claims canonical anchor tokens do not reliably
   * carry: SEP-10's registered claim set is `{iss, sub, iat, exp[, jti]}` — `aud` appears only in
   * the client-domain flow and `nbf` is not part of the scheme at all. Under this policy:
   *   * an ABSENT `aud`/`nbf` is accepted (there is nothing to check);
   *   * a PRESENT `aud` must still equal {@link VerifyJwsOptions.audience} exactly, and a PRESENT
   *     `nbf` still gates the window — presence keeps every discipline, absence only stops being
   *     its own refusal;
   *   * `iss`, `sub`, `iat`, `exp` stay REQUIRED exactly as under strict.
   * Fail-closed both ways: a token carrying MORE than it needs is never waved through on the
   * strength of the relaxed policy.
   */
  readonly claimPolicy?: 'strict' | 'sep10';
  /**
   * Optional replay hook. CONFIGURED: `jti` becomes a required claim and is first-sight checked
   * atomically through the store. UNCONFIGURED: tokens are NOT replay-checked — see
   * {@link REPLAY_UNCHECKED_NOTE}.
   */
  readonly replay?: { readonly store: JtiReplayStore; readonly provider: string };
}

/**
 * Verify a compact JWS and return its claims. Throws `JwsError` on EVERY failure — fail closed,
 * no boolean a caller can forget to check. Order matters and is deliberate:
 *
 *   1. structure (three segments, strict base64url),
 *   2. KEY TYPE pin (`keyAlgorithm` — the algorithm decision, made from the configured key, not
 *      the token: EC P-256 ⇒ ES256, OKP Ed25519 ⇒ EdDSA),
 *   3. header shape + alg agreement WITH the key-derived algorithm (still pre-crypto: cheap
 *      refusals first),
 *   4. signature over the exact `header.payload` ASCII bytes (only after this may payload claims
 *      be TRUSTED — an unsigned payload gets no claim parsing beyond shape). ES256: exactly-64-
 *      byte r‖s, DER-translated for node. EdDSA: exactly-64-byte ||R||S verified directly with
 *      digest `null`.
 *   5. claim presence/type per the configured claim policy (strict: none defaulted; sep10:
 *      aud/nbf optional but checked WHEN PRESENT), issuer equality, audience equality (strict) or
 *      when-present audience equality (sep10),
 *   6. temporal window under the INJECTED clock (nbf, then exp),
 *   7. optional jti replay (atomic first-sight; configured ⇒ mandatory jti).
 */
export async function verifyJws(token: string, options: VerifyJwsOptions): Promise<VerifiedJws> {
  const expectedAlg = keyAlgorithm(options.publicKey);

  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new JwsError('malformed-token', `refusing a JWS with ${parts.length} dot-separated segments; compact JWS has exactly 3`);
  }
  const [headerB64, payloadB64, signatureB64] = parts as [string, string, string];
  if (headerB64 !== frozenHeaderB64(expectedAlg)) {
    // Not merely unequal-to-ours: parse what WAS presented so the reason says why it is wrong
    // (a different alg label is the interesting case; everything else is bad-header noise).
    const presented = parseProtectedHeader(b64urlDecodeStrict(headerB64, 'header'));
    if (presented.alg !== expectedAlg) {
      throw new JwsError(
        expectedAlg === ES256 ? 'alg-not-es256' : 'alg-not-eddsa',
        `refusing a token whose header pins alg="${String(presented.alg)}"; the verification key ` +
          `is ${expectedAlg === ES256 ? 'EC P-256, which means ES256' : 'OKP Ed25519, which means EdDSA'} and ` +
          'NOTHING ELSE — alg:none, HS256-with-the-public-key, and cross-scheme relabelling are ' +
          'the classic confusion (see ' +
          'algorithm allowlist)',
      );
    }
    throw new JwsError(
      'bad-header',
      `refusing a token whose protected header is not exactly ${expectedAlg === ES256 ? PROTECTED_HEADER_JSON : EDDSA_PROTECTED_HEADER_JSON}`,
    );
  }

  const signature = b64urlDecodeStrict(signatureB64, 'signature');
  // ONLY exactly-64-byte signatures in BOTH schemes: ECDSA r‖s (32+32) or Ed25519 ||R||S. A
  // DER-encoded signature pasted into the compact field is ~70-72 bytes and is refused HERE,
  // explicitly — not silently parsed, not compared-and-failed — so the alert says "wrong
  // encoding", which is an integration bug, not an attack.
  if (signature.length !== 64) {
    throw new JwsError(
      'signature-length',
      `refusing a ${signature.length}-byte JWS signature; compact JWS carries exactly 64 bytes (${expectedAlg === ES256 ? 'r‖s, 32+32' : 'Ed25519 R then S'})`,
    );
  }

  const signingInput = Buffer.from(`${headerB64}.${payloadB64}`, 'ascii');
  const ok =
    expectedAlg === ES256
      ? cryptoVerify('sha256', signingInput, options.publicKey, rawToDer(signature))
      : cryptoVerify(null, signingInput, options.publicKey, signature);
  if (!ok) {
    throw new JwsError(
      'signature-mismatch',
      'refusing a token whose signature does not verify under the configured key over the exact ' +
        'header.payload bytes',
    );
  }

  // Signature held: the payload is now provably ours-or-the-holder's, and claim parsing begins.
  const payloadText = b64urlDecodeStrict(payloadB64, 'payload').toString('utf8');
  let parsed: unknown;
  try {
    parsed = JSON.parse(payloadText);
  } catch {
    throw new JwsError('payload-malformed', 'refusing a token whose payload segment is not valid JSON');
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new JwsError('payload-malformed', 'refusing a token whose payload is not a JSON object');
  }
  const bag = parsed as Record<string, unknown>;

  // Claim presence per policy (see VerifyJwsOptions.claimPolicy): strict requires every registered
  // claim; 'sep10' drops aud/nbf from the REQUIRED set — canonical anchor tokens carry
  // {iss, sub, iat, exp[, jti]} only. Presence-with-wrong-type stays a refusal under BOTH policies,
  // and the when-present checks below keep a present aud/nbf fully enforced.
  const sep10Claims = options.claimPolicy === 'sep10';
  const requiredStringClaims: readonly string[] = sep10Claims ? ['iss', 'sub'] : ['iss', 'sub', 'aud'];
  const requiredTimeClaims: readonly string[] = sep10Claims ? ['iat', 'exp'] : ['iat', 'nbf', 'exp'];

  for (const key of requiredStringClaims) {
    const v = bag[key];
    if (v === undefined) {
      throw new JwsError('claim-absent', `refusing a token without "${key}"; every claim is checked and NONE is defaulted`);
    }
    if (typeof v !== 'string' || v.length === 0) {
      throw new JwsError('claim-type', `refusing a token whose "${key}" is ${describe(v)}; expected a non-empty string`);
    }
  }
  for (const key of requiredTimeClaims) {
    const v = bag[key];
    if (v === undefined) {
      throw new JwsError('claim-absent', `refusing a token without "${key}"; an absent expiry must not mean "never expires"`);
    }
    if (typeof v !== 'number' || !Number.isSafeInteger(v)) {
      throw new JwsError('claim-type', `refusing a token whose "${key}" is ${describe(v)}; expected unix seconds as an integer`);
    }
  }
  // When-present type discipline for the two policy-optional claims.
  for (const key of ['aud', 'nbf']) {
    if (!sep10Claims || bag[key] === undefined) continue;
    if (key === 'aud') {
      if (typeof bag[key] !== 'string' || (bag[key] as string).length === 0) {
        throw new JwsError('claim-type', `refusing a token whose "${key}" is ${describe(bag[key])}; expected a non-empty string`);
      }
    } else if (typeof bag[key] !== 'number' || !Number.isSafeInteger(bag[key])) {
      throw new JwsError('claim-type', `refusing a token whose "${key}" is ${describe(bag[key])}; expected unix seconds as an integer`);
    }
  }

  if (bag['iss'] !== options.issuer) {
    throw new JwsError('issuer-mismatch', 'refusing a token issued by another issuer');
  }
  // String-form audience only: our issuer never emits the array form, so accepting one would
  // widen the accepted set for no interoperability we actually have. Under 'sep10' an ABSENT aud
  // passes (nothing to compare); a PRESENT one is still compared exactly.
  if ((!sep10Claims || bag['aud'] !== undefined) && bag['aud'] !== options.audience) {
    throw new JwsError(
      'audience-mismatch',
      sep10Claims
        ? 'refusing a token scoped to another audience (SEP-10 policy: aud is optional, but a token that CARRIES one must match)'
        : 'refusing a token scoped to another audience',
    );
  }

  // Temporal window under the INJECTED clock, before any stateful check burns a dedupe slot.
  const nbf = bag['nbf'] as number | undefined;
  const exp = bag['exp'] as number;
  if (nbf !== undefined && options.nowSeconds < nbf) {
    throw new JwsError('token-not-yet-valid', `refusing a token that is not valid until nbf=${nbf} (now ${options.nowSeconds})`);
  }
  if (options.nowSeconds >= exp) {
    throw new JwsError('token-expired', `refusing a token that expired at exp=${exp} (now ${options.nowSeconds})`);
  }

  let jti: string | undefined;
  if (options.replay !== undefined) {
    const presented = bag['jti'];
    if (typeof presented !== 'string' || presented.length === 0) {
      throw new JwsError(
        'claim-absent',
        'refusing a token without "jti" while a replay store is configured; a replay-checked ' +
          'scheme cannot silently exempt jti-less tokens, or the exemption is the bypass',
      );
    }
    const first = await options.replay.store.firstSight(options.replay.provider, presented, options.nowSeconds);
    if (!first) {
      throw new JwsError('replay-detected', 'refusing a token whose jti has already been seen (replay)');
    }
    jti = presented;
  } else if (bag['jti'] !== undefined) {
    const presented = bag['jti'];
    if (typeof presented !== 'string' || presented.length === 0) {
      throw new JwsError('claim-type', `refusing a token whose "jti" is ${describe(presented)}; expected a non-empty string`);
    }
    // NO replay check on this branch — see REPLAY_UNCHECKED_NOTE. Documented absence, never silence.
    jti = presented;
  }

  return {
    iss: bag['iss'] as string,
    sub: bag['sub'] as string,
    ...(bag['aud'] === undefined ? {} : { aud: bag['aud'] as string }),
    iat: bag['iat'] as number,
    ...(nbf === undefined ? {} : { nbf }),
    exp,
    ...(jti === undefined ? {} : { jti }),
  };
}

/** Shape-check a presented header far enough to name the refusal precisely. */
function parseProtectedHeader(headerBytes: Buffer): { alg: unknown } {
  let parsed: unknown;
  try {
    parsed = JSON.parse(headerBytes.toString('utf8'));
  } catch {
    throw new JwsError('bad-header', 'refusing a token whose header segment is not valid JSON');
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new JwsError('bad-header', 'refusing a token whose header is not a JSON object');
  }
  const bag = parsed as Record<string, unknown>;
  // Embedded-key headers (jwk/jku/x5u/x5c) try to make the verifier adopt ATTACKER-chosen key
  // material. Our key arrives by configuration; these parameters are refused outright rather
  // than ignored, so a future refactor cannot grow a "trust the token's key" path unnoticed.
  if ('jwk' in bag || 'jku' in bag || 'x5u' in bag || 'x5c' in bag) {
    throw new JwsError('bad-header', 'refusing a token whose header embeds or points at key material (jwk/jku/x5u/x5c); the verification key comes from configuration only');
  }
  if ('crit' in bag) {
    throw new JwsError('bad-header', 'refusing a token declaring critical header extensions (crit) this verifier does not implement');
  }
  return { alg: bag['alg'] };
}
