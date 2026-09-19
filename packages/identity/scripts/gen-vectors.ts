/**
 * Known-answer test vector generator.
 *
 * Run: `npm run vectors -w packages/identity`  (add `--force` to regenerate proofs)
 *
 * DETERMINISM, HONESTLY:
 *   - Issuer key and BBS+ SIGNATURE are fully deterministic from the 32-byte seed. BBS Sign is
 *     a deterministic algorithm; regenerating always reproduces the same bytes.
 *   - BBS+ PROOFS ARE NOT. ProofGen samples fresh randomness on every call (that randomness is
 *     what buys unlinkability, §7.4 item 5) and @digitalbazaar/bbs-signatures@3.1.0 exposes no
 *     hook to inject it. So proofs are CAPTURED ONCE and FROZEN in fixtures/vectors.json.
 *     This script reuses existing proof bytes unless --force is passed, so a routine re-run does
 *     not silently invalidate the Rust verifier's fixtures.
 *
 * The Rust `kyc-gate` verifier is tested against these exact bytes, so both the compressed
 * (BBS+ wire) and the uncompressed (Soroban host) forms are emitted for every point.
 */

import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  BINDING_DOMAIN,
  CIPHERSUITE,
  CLAIM_INDEX,
  CLAIM_SPECS,
  CREDENTIAL_HEADER,
  SCHEMA_ATTRIBUTE_COUNT,
  SCHEMA_VERSION,
  canonicalBindingBytes,
  bindingDigest,
  decompressG1,
  decompressG2,
  derive,
  expectedProofBytes,
  flattenSorobanProof,
  generateIssuerKeyPair,
  issue,
  issuerIdFromPublicKey,
  PRESENTATION_HEADER_DOMAIN,
  PROOF_MAX_WINDOW,
  presentationHeaderFor,
  splitProof,
  splitSignature,
  toHex,
  type KycClaims,
  type ProofBinding,
} from '../dist/index.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const OUT = join(HERE, '..', 'fixtures', 'vectors.json');
const FORCE = process.argv.includes('--force');

/** Fixed seed. Never change it — the Rust fixtures are pinned to the key it produces. */
const ISSUER_SEED = Uint8Array.from({ length: 32 }, (_, i) => i + 1);
/** A second issuer, for the wrong-key negative vector. */
const OTHER_SEED = Uint8Array.from({ length: 32 }, (_, i) => 0xa0 + i);

const utf8 = new TextEncoder();

const sha256 = (b: Uint8Array): Uint8Array => Uint8Array.from(createHash('sha256').update(b).digest());

const CLAIMS_BASE = {
  schemaVersion: SCHEMA_VERSION,
  revocationIndex: 4242,
  // 2026-01-01T00:00:00Z / 2026-07-01T00:00:00Z — fixed, so the file is diff-stable.
  issuedAt: 1767225600,
  expiresAt: 1782950400,
  subjectBinding: '3d1f2b6a9c8e4705b1d2c3a4f5e6978899aabbccddeeff00112233445566778899'.slice(0, 64),
  over18: true,
  over21: true,
  notSanctioned: true,
  notPep: true,
  jurisdictionOk: true,
  livenessOk: true,
} as const;

/**
 * The gate contract these vectors are bound to.
 *
 * IT IS A UNIT-TEST ADDRESS, NOT A DEPLOYMENT. `StrKey.encodeContract(sha256(
 * "stellaronramp/test-gate/v1"))`, so it is reproducible and provably not any live contract.
 * `contracts/kyc-gate/src/test.rs` registers the gate AT this address (`Env::register_at`), which
 * is what lets the Rust verifier re-derive the presentation header and match these bytes.
 *
 * REGISTRY address, not a gate at all. Nothing noticed because, until `attest_bbs` derived the
 * header itself, nothing on chain ever looked at `contractId`.
 *
 * CONSEQUENCE, DELIBERATE: the frozen vectors can no longer be replayed against the live deployed
 * gate. `attest_bbs` derives the header from its OWN address, and that address is not this one, so
 * every one of these proofs is rejected off the test bench. That is the fix working. A live
 * demonstration has to derive a proof at runtime against the real gate id.
 */
const TEST_GATE_CONTRACT_ID = 'CDL45EUB2GIFFP2KJG4ULBLAIB6VT7HWGVPI65T6G6VEZOTULWPSQZI6';

/** An address the frozen proof is NOT bound to, used by the `wrong-wallet` negative vector. */
const OTHER_WALLET = 'GDYSMOGGSUXM7W36ORWLWGA4MI2YUSKJX4243SZGKFRHMEH5AZKB6YQ6';
const RUST_TEST_START_SEQ = 1_000;

const BASE_BINDING: ProofBinding = {
  nonce: '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff',
  // The Rust test passes exactly this address as `subject`. It is bound into the presentation
  // header, and `attest_bbs` now re-derives that header from the `subject` it was called with —
  // so submitting this proof for any other address fails the challenge check.
  walletAddress: 'CBQHNAXSI55GX2GN6D67GK7BHVPSLJUGZQEU7WJ5LKR5PNUCGLIMAO4K',
  contractId: TEST_GATE_CONTRACT_ID,
  networkPassphrase: 'Test SDF Network ; September 2015',
  // EXACTLY `START_SEQ + PROOF_MAX_WINDOW`, deliberately: the widest window `attest_bbs` will
  // accept from the ledger the Rust suite attests at. It was 1_500_000 (~87 days ahead of
  // START_SEQ) — a freshness window so wide the proof was a near-permanent bearer token, and
  // wider than the ~1-day consumed-nonce tombstone that is supposed to stop it being replayed
  // compliance revocation). Sitting exactly ON the boundary means the Rust happy path exercises
  // the widest legal window, and the tombstone/freshness interlock is exercised at its tightest
  // point — `PROOF_MAX_WINDOW == NONCE_MIN_TTL`, so the tombstone outlives the window by 0
  // ledgers and any future widening of the window is a live test failure, not a silent hole.
  ledgerExpiry: RUST_TEST_START_SEQ + PROOF_MAX_WINDOW,
};

interface CaseSpec {
  readonly name: string;
  readonly note: string;
  readonly disclose: readonly number[];
  readonly binding: ProofBinding;
}

const CASES: readonly CaseSpec[] = [
  {
    name: 'standard-onramp',
    note: 'over18 AND notSanctioned — the default gate. R=2, U=10.',
    disclose: [CLAIM_INDEX.over18, CLAIM_INDEX.notSanctioned],
    binding: BASE_BINDING,
  },
  {
    name: 'over18-only',
    note: 'Minimum disclosure for an age gate. R=1, U=11.',
    disclose: [CLAIM_INDEX.over18],
    binding: BASE_BINDING,
  },
  {
    name: 'empty-disclosure',
    note: 'Proves possession of a valid credential and nothing else. R=0, U=12.',
    disclose: [],
    binding: BASE_BINDING,
  },
  {
    name: 'full-disclosure',
    note: 'Every attribute revealed. R=12, U=0 — the proof-size floor, 272 bytes.',
    disclose: CLAIM_SPECS.map((s) => s.index).sort((a, b) => a - b),
    binding: BASE_BINDING,
  },
  {
    name: 'metadata-plus-gate',
    note: 'What kyc-gate.attest_bbs actually needs: revocationIndex + expiry + subject binding + the two gate booleans.',
    disclose: [
      CLAIM_INDEX.revocationIndex,
      CLAIM_INDEX.expiresAt,
      CLAIM_INDEX.subjectBinding,
      CLAIM_INDEX.over18,
      CLAIM_INDEX.notSanctioned,
    ].sort((a, b) => a - b),
    binding: BASE_BINDING,
  },
  {
    name: 'gate-onramp',
    note:
      'The on-ramp disclosure set {0,1,2,3,4,5,6,8} — what gateOnrampPredicate() ' +
      'returns. R=8, U=4, 400 bytes. This is the case the Rust ' +
      'attest_bbs verifier should cross-check its issuer_id / revocation_index / expires_at ' +
      'arguments against.',
    disclose: [
      CLAIM_INDEX.schemaVersion,
      CLAIM_INDEX.issuerId,
      CLAIM_INDEX.revocationIndex,
      CLAIM_INDEX.issuedAt,
      CLAIM_INDEX.expiresAt,
      CLAIM_INDEX.subjectBinding,
      CLAIM_INDEX.over18,
      CLAIM_INDEX.notSanctioned,
    ].sort((a, b) => a - b),
    binding: BASE_BINDING,
  },
  {
    name: 'gate-onramp-second-nonce',
    note:
      'Byte-identical to gate-onramp except for the binding NONCE. Exists because attest_bbs now ' +
      'CONSUMES the nonce: any Rust test that attests a second time for the same subject (revoke ' +
      'then re-submit, stale-expiry ordering) needs a second, independently valid proof. Same ' +
      'subject, same gate, same network, same ledgerExpiry.',
    disclose: [
      CLAIM_INDEX.schemaVersion,
      CLAIM_INDEX.issuerId,
      CLAIM_INDEX.revocationIndex,
      CLAIM_INDEX.issuedAt,
      CLAIM_INDEX.expiresAt,
      CLAIM_INDEX.subjectBinding,
      CLAIM_INDEX.over18,
      CLAIM_INDEX.notSanctioned,
    ].sort((a, b) => a - b),
    binding: {
      ...BASE_BINDING,
      nonce: '0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0',
    },
  },
  {
    name: 'other-contract',
    note: 'Identical disclosure, different contractId. Verifying this against BASE_BINDING must fail.',
    disclose: [CLAIM_INDEX.over18, CLAIM_INDEX.notSanctioned],
    binding: { ...BASE_BINDING, contractId: 'CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC' },
  },
  {
    name: 'expired-bound',
    note: 'ledgerExpiry already in the past. Cryptographically valid, operationally dead.',
    disclose: [CLAIM_INDEX.over18, CLAIM_INDEX.notSanctioned],
    binding: { ...BASE_BINDING, ledgerExpiry: 1000 },
  },
];

function hexPoint(compressed: Uint8Array, kind: 'g1' | 'g2'): { compressed: string; uncompressed: string } {
  return {
    compressed: toHex(compressed),
    uncompressed: toHex(kind === 'g1' ? decompressG1(compressed) : decompressG2(compressed)),
  };
}

function loadExisting(): Record<string, unknown> | undefined {
  if (FORCE) return undefined;
  try {
    return JSON.parse(readFileSync(OUT, 'utf8')) as Record<string, unknown>;
  } catch {
    return undefined;
  }
}

async function main(): Promise<void> {
  const issuer = await generateIssuerKeyPair(ISSUER_SEED);
  const other = await generateIssuerKeyPair(OTHER_SEED);
  const issuerId = issuerIdFromPublicKey(issuer.publicKey);

  const claims: KycClaims = { ...CLAIMS_BASE, issuerId };
  const credential = await issue(claims, issuer.secretKey);
  const sig = splitSignature(credential.signature);

  const existing = loadExisting();
  const existingCases = new Map<string, { proof: string; bindingDigest: string }>();
  if (existing !== undefined && Array.isArray(existing.cases)) {
    for (const c of existing.cases as Array<{
      name?: string;
      proof?: { compressed?: string };
      bindingDigest?: string;
    }>) {
      if (typeof c.name === 'string' && typeof c.proof?.compressed === 'string') {
        // A frozen proof with no recorded binding digest predates this guard; treat it as
        // unmatchable so it is regenerated rather than silently reused under a new binding.
        existingCases.set(c.name, {
          proof: c.proof.compressed,
          bindingDigest: typeof c.bindingDigest === 'string' ? c.bindingDigest : '',
        });
      }
    }
  }
  // Only reuse frozen proofs if the credential they were made against is unchanged.
  const sameCredential =
    existing !== undefined &&
    (existing.credential as { signature?: string } | undefined)?.signature === toHex(credential.signature);

  const cases = [];
  for (const spec of CASES) {
    const u = SCHEMA_ATTRIBUTE_COUNT - spec.disclose.length;
    const digest = toHex(bindingDigest(spec.binding));
    // REUSE IS CONDITIONAL ON THE BINDING, NOT JUST THE CREDENTIAL. The presentation header is
    // inside the Fiat-Shamir challenge, so a proof frozen under binding X does not verify under
    // binding Y. Without this, editing BASE_BINDING left every case's proof bytes untouched and
    // the whole file quietly self-inconsistent — which is exactly the class of "nothing looked at
    // contractId" mistake this change exists to fix.
    const prior = sameCredential ? existingCases.get(spec.name) : undefined;
    const frozen = prior?.bindingDigest === digest ? prior : undefined;
    const proofBytes = frozen
      ? Uint8Array.from(Buffer.from(frozen.proof, 'hex'))
      : (await derive(credential, spec.disclose, spec.binding)).proof;

    if (proofBytes.length !== expectedProofBytes(u)) {
      throw new Error(`case ${spec.name}: proof size law violated`);
    }
    const sp = splitProof(proofBytes);
    cases.push({
      name: spec.name,
      note: spec.note,
      frozen: frozen !== undefined,
      disclosedIndexes: [...spec.disclose],
      disclosedMessages: spec.disclose.map((i) => credential.messages[i]),
      undisclosedCount: u,
      binding: spec.binding,
      bindingCanonicalBytes: toHex(canonicalBindingBytes(spec.binding)),
      bindingDigest: digest,
      presentationHeader: toHex(presentationHeaderFor(spec.binding)),
      // The five values `kyc-gate.attest_bbs` needs to RE-DERIVE `presentationHeader` itself.
      // `subject`, `contract` and `networkId` come from the chain (`subject` argument,
      // `env.current_contract_address()`, `env.ledger().network_id()`); `nonceHex` and
      // `ledgerExpiry` are the two arguments the entry point gained. Emitted explicitly because
      // the Rust test is `no_std` and cannot sha256 the passphrase to check its own env.
      sorobanBinding: {
        subject: spec.binding.walletAddress,
        contract: spec.binding.contractId,
        nonceHex: spec.binding.nonce,
        ledgerExpiry: spec.binding.ledgerExpiry,
        networkId: toHex(sha256(utf8.encode(spec.binding.networkPassphrase))),
      },
      proof: {
        compressed: toHex(proofBytes),
        length: proofBytes.length,
        sizeLaw: `144 + 32*(4 + ${u}) = ${expectedProofBytes(u)}`,
      },
      soroban: {
        abar: toHex(sp.abar),
        bbar: toHex(sp.bbar),
        d: toHex(sp.d),
        eHat: toHex(sp.eHat),
        r1Hat: toHex(sp.r1Hat),
        r3Hat: toHex(sp.r3Hat),
        mHat: sp.mHat.map(toHex),
        challenge: toHex(sp.challenge),
        flat: toHex(flattenSorobanProof(sp)),
        flatLength: flattenSorobanProof(sp).length,
      },
      expect: { verify: true },
    });
  }

  const standard = cases.find((c) => c.name === 'standard-onramp');
  if (standard === undefined) throw new Error('missing standard-onramp case');
  const stdProof = Uint8Array.from(Buffer.from(standard.proof.compressed, 'hex'));

  // Deterministic mutations of the standard proof. Every one of these MUST verify false.
  const flip = (offset: number): string => {
    const copy = Uint8Array.from(stdProof);
    copy[offset] = ((copy[offset] ?? 0) ^ 0x01) & 0xff;
    return toHex(copy);
  };
  const negative = [
    {
      name: 'tampered-challenge',
      note: 'Low bit of the final challenge scalar flipped. Parses fine; the math must reject.',
      basedOn: 'standard-onramp',
      mutation: { kind: 'flip-bit', byteOffset: stdProof.length - 1, bit: 0 },
      proof: { compressed: flip(stdProof.length - 1) },
      expect: { verify: false, reason: 'bbs-invalid' },
    },
    {
      name: 'tampered-abar',
      note:
        'Low bit of the compressed Abar point flipped. In principle this can die at point ' +
        'decode OR in the pairing; against THESE frozen bytes it deterministically dies at ' +
        'decode, so the reason is pinned to malformed-proof rather than left as an alternation ' +
        ' — a `bbs-invalid|malformed-proof` would let a real change, ' +
        'e.g. the curve library returning false where it used to throw, pass unnoticed. It read ' +
        '"bbs-invalid-or-malformed" until the small-items pass, and "malformed" is not a ' +
        'reason, so nothing could assert it — which is how this case sat in the generic ' +
        '`error` bucket unnoticed.',
      basedOn: 'standard-onramp',
      mutation: { kind: 'flip-bit', byteOffset: 47, bit: 0 },
      proof: { compressed: flip(47) },
      expect: { verify: false, reason: 'malformed-proof' },
    },
    {
      name: 'tampered-mhat0',
      note: 'First hidden-message response corrupted — this is the "lie about a hidden attribute" case.',
      basedOn: 'standard-onramp',
      mutation: { kind: 'flip-bit', byteOffset: 144 + 3 * 32, bit: 0 },
      proof: { compressed: flip(144 + 3 * 32) },
      expect: { verify: false, reason: 'bbs-invalid' },
    },
    {
      name: 'wrong-issuer-key',
      note: 'Untouched standard-onramp proof verified against a different issuer public key.',
      basedOn: 'standard-onramp',
      mutation: { kind: 'substitute-public-key' },
      publicKey: hexPoint(other.publicKey, 'g2'),
      expect: { verify: false, reason: 'bbs-invalid' },
    },
    {
      name: 'wrong-nonce',
      note: 'Untouched proof verified against a binding whose nonce differs in one nibble.',
      basedOn: 'standard-onramp',
      mutation: { kind: 'substitute-binding' },
      binding: { ...BASE_BINDING, nonce: `${BASE_BINDING.nonce.slice(0, 63)}0` },
      presentationHeader: toHex(
        presentationHeaderFor({ ...BASE_BINDING, nonce: `${BASE_BINDING.nonce.slice(0, 63)}0` }),
      ),
      expect: { verify: false, reason: 'binding-mismatch' },
    },
    {
      name: 'wrong-contract',
      note: 'The other-contract proof verified against BASE_BINDING — cross-contract replay.',
      basedOn: 'other-contract',
      mutation: { kind: 'substitute-binding' },
      binding: BASE_BINDING,
      expect: { verify: false, reason: 'binding-mismatch' },
    },
    {
      name: 'wrong-wallet',
      note:
        'An untouched proof verified against a binding whose walletAddress is a different ' +
        'holder: the proof must not verify. Also the only vector that canonicalises a G-address, ' +
        'so a strkey-length assumption in canonicalBindingBytes would go red here.',
      basedOn: 'standard-onramp',
      mutation: { kind: 'substitute-binding' },
      binding: { ...BASE_BINDING, walletAddress: OTHER_WALLET },
      presentationHeader: toHex(presentationHeaderFor({ ...BASE_BINDING, walletAddress: OTHER_WALLET })),
      expect: { verify: false, reason: 'binding-mismatch' },
    },
    {
      name: 'wrong-wallet-rewritten-binding',
      note:
        'THE SAME REPLAY, BY A STRONGER ATTACKER. wrong-wallet leaves the proof struct declaring ' +
        'the binding it was derived for, so a TypeScript verifier rejects it at the ' +
        'self-declared binding digest compare (`binding-mismatch`) long before any cryptography ' +
        'runs. Here the attacker ALSO rewrites the declared binding to the victim’s, so that ' +
        'door cannot answer and the rejection must come from the BBS+ math: the presentation ' +
        'header is derived from the binding, so the challenge no longer reproduces and ' +
        'ProofVerify fails (`bbs-invalid`). This is the case the Rust verifier must reproduce — ' +
        'it has no self-declared binding and therefore cannot ever answer `binding-mismatch`. ' +
        'Same walletAddress as wrong-wallet: the address a replay would target ' +
        'frozen proof to.',
      basedOn: 'standard-onramp',
      mutation: { kind: 'substitute-binding', declaredBindingRewritten: true },
      binding: { ...BASE_BINDING, walletAddress: OTHER_WALLET },
      presentationHeader: toHex(presentationHeaderFor({ ...BASE_BINDING, walletAddress: OTHER_WALLET })),
      // The runner presents the proof as DECLARING the target binding, not the honest one.
      declaredBinding: 'target',
      expect: { verify: false, reason: 'bbs-invalid' },
    },
    {
      name: 'swapped-disclosed-messages',
      note: 'Correct proof, but the two disclosed messages are supplied in reversed order.',
      basedOn: 'standard-onramp',
      mutation: { kind: 'swap-disclosed-messages' },
      disclosedIndexes: [CLAIM_INDEX.over18, CLAIM_INDEX.notSanctioned],
      disclosedMessages: [
        credential.messages[CLAIM_INDEX.notSanctioned],
        credential.messages[CLAIM_INDEX.over18],
      ],
      expect: { verify: false, reason: 'message-index-mismatch' },
    },
    {
      name: 'claims-undisclosed-index',
      note: 'Proof for {6,8} presented as if it also disclosed index 7 (over21). U no longer matches the byte length.',
      basedOn: 'standard-onramp',
      mutation: { kind: 'add-claimed-index' },
      disclosedIndexes: [CLAIM_INDEX.over18, CLAIM_INDEX.over21, CLAIM_INDEX.notSanctioned],
      disclosedMessages: [
        credential.messages[CLAIM_INDEX.over18],
        credential.messages[CLAIM_INDEX.over21],
        credential.messages[CLAIM_INDEX.notSanctioned],
      ],
      expect: { verify: false, reason: 'disclosure-shape' },
    },
  ];

  const doc = {
    $comment:
      'Known-answer vectors for @stellaronramp/identity. The Rust kyc-gate verifier is tested ' +
      'against these EXACT bytes. Keys and the signature are reproducible from issuer.seed; ' +
      'proofs are randomised by ProofGen and are therefore FROZEN, not reproducible.',
    version: 1,
    generator: '@stellaronramp/identity scripts/gen-vectors.ts',
    ciphersuite: CIPHERSUITE,
    encoding: 'all byte fields are lowercase hex, no 0x prefix',

    layout: {
      $comment:
        'Soroban host rejects the compression flag and provides no decompression host function ' +
        '. The SDK decompresses; these are the exact forms the host accepts.',
      g1Compressed: 48,
      g1Uncompressed: 96,
      g1UncompressedLayout: 'be(X) || be(Y), each 48 bytes big-endian',
      g2Compressed: 96,
      g2Uncompressed: 192,
      g2UncompressedLayout: 'be(X_c1) || be(X_c0) || be(Y_c1) || be(Y_c0), each 48 bytes big-endian',
      scalar: 32,
      scalarLayout: 'big-endian integer mod r',
      signatureLayout: 'A (48, compressed G1) || e (32, scalar) = 80 bytes',
      proofWireOrder: [
        'Abar (48, compressed G1)',
        'Bbar (48, compressed G1)',
        'D    (48, compressed G1)',
        'eHat (32)',
        'r1Hat (32)',
        'r3Hat (32)',
        'mHat_1..mHat_U (32 each)',
        'challenge (32)  <- LAST, after the mHat block',
      ],
      proofSizeLaw: '144 + 32*(4 + U)  where U = undisclosed message count',
      sorobanFlatProofLayout:
        'abar(96) || bbar(96) || d(96) || eHat(32) || r1Hat(32) || r3Hat(32) || mHat*(32U) || challenge(32)',
      sorobanFlatProofSizeLaw: '288 + 32*(4 + U)',
    },

    presentationBinding: {
      $comment:
        'The presentation header is DERIVED, never supplied. kyc-gate.attest_bbs recomputes it ' +
        'from {subject, current_contract_address, network_id, nonce, ledger_expiry} and compares ' +
        'nothing — there is no caller-supplied header left to compare against. src/binding.ts is ' +
        'the reference implementation; contracts/kyc-gate/src/lib.rs mirrors it byte for byte.',
      bindingDomain: BINDING_DOMAIN,
      presentationHeaderDomain: PRESENTATION_HEADER_DOMAIN,
      canonicalLayout: [
        'LP(utf8(bindingDomain))',
        'LP(nonce)                 // 32 RAW bytes, not hex',
        'LP(utf8(walletAddress))   // 56-char strkey',
        'LP(utf8(contractId))      // 56-char strkey',
        'LP(sha256(utf8(networkPassphrase)))   // == Soroban env.ledger().network_id()',
        'LP(u32be(ledgerExpiry))',
      ],
      lengthPrefix: 'every field carries a 4-byte big-endian length prefix',
      bindingDigest: 'sha256(canonical)',
      presentationHeader: 'sha256(utf8(presentationHeaderDomain) || bindingDigest)',
      proofMaxWindow: PROOF_MAX_WINDOW,
      proofMaxWindowRule:
        'kyc-gate.attest_bbs refuses ledgerExpiry - current_ledger > proofMaxWindow with ' +
        'ExpiryTooFar. The bound is PROOF_MAX_WINDOW == NONCE_MIN_TTL, so the consumed-nonce ' +
        'tombstone always outlives the freshness window and a proof can never come back after ' +
        'its tombstone is evicted.',
      testGateContractId: TEST_GATE_CONTRACT_ID,
      testGateContractIdDerivation: 'StrKey.encodeContract(sha256("stellaronramp/test-gate/v1"))',
    },

    schema: {
      version: SCHEMA_VERSION,
      attributeCount: SCHEMA_ATTRIBUTE_COUNT,
      header: CREDENTIAL_HEADER,
      headerHex: toHex(utf8.encode(CREDENTIAL_HEADER)),
      messageEncoding: 'utf8("<claimName>=<canonicalValue>")',
      attributes: CLAIM_SPECS.map((s) => ({ index: s.index, name: s.name, kind: s.kind })),
    },

    issuer: {
      seed: toHex(ISSUER_SEED),
      secretKey: toHex(issuer.secretKey),
      publicKey: hexPoint(issuer.publicKey, 'g2'),
      issuerId,
    },
    otherIssuer: {
      $comment: 'Used only by the wrong-issuer-key negative vector.',
      seed: toHex(OTHER_SEED),
      publicKey: hexPoint(other.publicKey, 'g2'),
      issuerId: issuerIdFromPublicKey(other.publicKey),
    },

    credential: {
      claims,
      messages: credential.messages,
      messagesHex: credential.messages.map((m) => toHex(utf8.encode(m))),
      signature: toHex(credential.signature),
      signatureA: { compressed: toHex(credential.signature.subarray(0, 48)), uncompressed: toHex(sig.a) },
      signatureE: toHex(sig.e),
      expect: { verifySignature: true },
    },

    cases,
    negative,
  };

  mkdirSync(dirname(OUT), { recursive: true });
  writeFileSync(OUT, `${JSON.stringify(doc, null, 2)}\n`);
  const reused = cases.filter((c) => c.frozen).length;
  process.stdout.write(
    `wrote ${OUT}\n  ${cases.length} positive cases (${reused} frozen, ${cases.length - reused} newly generated)\n` +
      `  ${negative.length} negative cases\n`,
  );
}

await main();
