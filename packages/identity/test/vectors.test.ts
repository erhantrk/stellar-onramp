/**
 * fixtures/vectors.json is a CONTRACT with the Rust `kyc-gate` verifier, which will be tested
 * against these exact bytes. If a change here makes this file fail, the Rust side breaks too —
 * that is the point.
 */

import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import {
  UNSAFE_NO_CHECKS,
  CIPHERSUITE,
  CREDENTIAL_HEADER,
  SCHEMA_ATTRIBUTE_COUNT,
  SCHEMA_VERSION,
  bindingDigestHex,
  canonicalBindingBytes,
  decompressG1,
  decompressG2,
  deserializeProof,
  expectedProofBytes,
  flattenSorobanProof,
  generateIssuerKeyPair,
  issue,
  issuerIdFromPublicKey,
  PROOF_MAX_WINDOW,
  presentationHeaderFor,
  splitProof,
  splitSignature,
  toHex,
  verify,
  verifyCredential,
  verifyDetailed,
  type ProofBinding,
  type VerifyFailure,
} from '../src/index.js';

/**
 * Every `VerifyFailure` member, as a VALUE, so a fixture cannot declare a reason that does not
 * exist — which is exactly how `tampered-abar` declared "bbs-invalid-or-malformed" and was
 * asserted by nothing for the whole life of the file.
 *
 * `satisfies` catches a member that is not real; `Missing` catches one that is real and absent,
 * so renaming a reason in credential.ts turns this file red rather than silently narrowing the
 * set a fixture is allowed to name.
 */
const REASONS = [
  'schema-version',
  'binding-mismatch',
  'binding-invalid',
  'expired',
  'credential-expired',
  'subject-mismatch',
  'malformed-proof',
  'disclosure-shape',
  'unknown-index',
  'message-index-mismatch',
  'claim-mismatch',
  'revoked',
  'status-list-invalid',
  'replayed',
  'bbs-invalid',
  'error',
] as const satisfies readonly VerifyFailure[];
type MissingReason = Exclude<VerifyFailure, (typeof REASONS)[number]>;
const _reasonsAreExhaustive: [MissingReason] extends [never] ? true : MissingReason = true;
void _reasonsAreExhaustive;


const HERE = dirname(fileURLToPath(import.meta.url));
const VECTORS = JSON.parse(
  readFileSync(join(HERE, '..', 'fixtures', 'vectors.json'), 'utf8'),
) as VectorFile;

interface VectorCase {
  name: string;
  disclosedIndexes: number[];
  disclosedMessages: string[];
  undisclosedCount: number;
  binding: ProofBinding;
  bindingCanonicalBytes: string;
  bindingDigest: string;
  presentationHeader: string;
  sorobanBinding: {
    subject: string;
    contract: string;
    nonceHex: string;
    ledgerExpiry: number;
    networkId: string;
  };
  proof: { compressed: string; length: number };
  soroban: {
    abar: string;
    bbar: string;
    d: string;
    eHat: string;
    r1Hat: string;
    r3Hat: string;
    mHat: string[];
    challenge: string;
    flat: string;
    flatLength: number;
  };
  expect: { verify: boolean };
}

interface VectorNegative {
  name: string;
  basedOn: string;
  proof?: { compressed: string };
  publicKey?: { compressed: string; uncompressed: string };
  binding?: ProofBinding;
  disclosedIndexes?: number[];
  disclosedMessages?: string[];
  /**
   * WHICH binding the presented `Proof` STRUCT declares as its own, independent of the one it is
   * verified against. Default `'base'` — the honest binding the proof was derived for, which is
   * what a replay looks like from outside.
   *
   * `'target'` models the STRONGER attacker: one who also rewrites the struct's self-declared
   * binding to the victim's, so `verifyDetailed`'s digest compare cannot fire and the rejection
   * cross-language contract for a Rust verifier, which has no self-declared binding to compare
   * and therefore CANNOT answer `binding-mismatch` — pinning only the TypeScript structural door
   * for the replay cases would hand the Rust side a reason it can never produce.
   */
  declaredBinding?: 'base' | 'target';
  /**
   * `reason` is REQUIRED and is a single `VerifyFailure` member. Alternations were briefly
   * allowed (`'a|b'`) for `tampered-abar`; they are not, because the proof BYTES in this file are
   * frozen, so every outcome here is deterministic and an alternation only hides a real change
   *
   * so `valid === false` was the entire contract and a case could fail for a reason nobody
   * intended. `tampered-abar` did: it declared `bbs-invalid-or-malformed` and actually returned
   * `error`, the catch-all for an escaped exception. See the note on that case.
   */
  expect: { verify: boolean; reason: string };
}

interface VectorFile {
  version: number;
  ciphersuite: string;
  layout: Record<string, unknown>;
  schema: { version: string; attributeCount: number; header: string; headerHex: string };
  issuer: { seed: string; secretKey: string; publicKey: { compressed: string; uncompressed: string }; issuerId: string };
  otherIssuer: { publicKey: { compressed: string; uncompressed: string } };
  credential: {
    claims: Record<string, unknown>;
    messages: string[];
    signature: string;
    signatureA: { compressed: string; uncompressed: string };
    signatureE: string;
  };
  cases: VectorCase[];
  negative: VectorNegative[];
}

const hex = (s: string): Uint8Array => Uint8Array.from(Buffer.from(s, 'hex'));
const sha256 = (b: Uint8Array): Uint8Array => Uint8Array.from(createHash('sha256').update(b).digest());

describe('vectors.json — file-level invariants', () => {
  it('pins the ciphersuite, schema and header', () => {
    expect(VECTORS.ciphersuite).toBe(CIPHERSUITE);
    expect(VECTORS.schema.version).toBe(SCHEMA_VERSION);
    expect(VECTORS.schema.attributeCount).toBe(SCHEMA_ATTRIBUTE_COUNT);
    expect(VECTORS.schema.header).toBe(CREDENTIAL_HEADER);
    expect(hex(VECTORS.schema.headerHex)).toEqual(new TextEncoder().encode(CREDENTIAL_HEADER));
  });

  it('documents the exact Soroban byte layout the Rust side depends on', () => {
    expect(VECTORS.layout).toMatchObject({
      g1Compressed: 48,
      g1Uncompressed: 96,
      g2Compressed: 96,
      g2Uncompressed: 192,
      scalar: 32,
      proofSizeLaw: '144 + 32*(4 + U)  where U = undisclosed message count',
      sorobanFlatProofSizeLaw: '288 + 32*(4 + U)',
    });
  });
});

describe('vectors.json — deterministic sections are reproducible from the seed', () => {
  it('regenerates the issuer key exactly', async () => {
    const kp = await generateIssuerKeyPair(hex(VECTORS.issuer.seed));
    expect(toHex(kp.secretKey)).toBe(VECTORS.issuer.secretKey);
    expect(toHex(kp.publicKey)).toBe(VECTORS.issuer.publicKey.compressed);
    expect(toHex(decompressG2(kp.publicKey))).toBe(VECTORS.issuer.publicKey.uncompressed);
    expect(issuerIdFromPublicKey(kp.publicKey)).toBe(VECTORS.issuer.issuerId);
  });

  it('regenerates the credential signature exactly (BBS Sign is deterministic)', async () => {
    const kp = await generateIssuerKeyPair(hex(VECTORS.issuer.seed));
    const cred = await issue(VECTORS.credential.claims as never, kp.secretKey);
    expect(cred.messages).toEqual(VECTORS.credential.messages);
    expect(toHex(cred.signature)).toBe(VECTORS.credential.signature);
    expect(await verifyCredential(cred)).toBe(true);
  });

  it('emits both compressed and uncompressed forms of the signature point', () => {
    const sig = hex(VECTORS.credential.signature);
    expect(sig.length).toBe(80);
    const { a, e } = splitSignature(sig);
    expect(toHex(a)).toBe(VECTORS.credential.signatureA.uncompressed);
    expect(toHex(e)).toBe(VECTORS.credential.signatureE);
    expect(toHex(decompressG1(hex(VECTORS.credential.signatureA.compressed)))).toBe(
      VECTORS.credential.signatureA.uncompressed,
    );
    expect(a.length).toBe(96);
  });

  it('regenerates every binding digest and presentation header', () => {
    for (const c of VECTORS.cases) {
      expect(toHex(canonicalBindingBytes(c.binding))).toBe(c.bindingCanonicalBytes);
      expect(bindingDigestHex(c.binding)).toBe(c.bindingDigest);
      expect(toHex(presentationHeaderFor(c.binding))).toBe(c.presentationHeader);
    }
  });

  /**
   * `sorobanBinding` is what `contracts/kyc-gate/src/test.rs` reads to pin BOTH sides of the
   * drifts from `binding`, the Rust suite pins the wrong context and the cross-language contract
   * is silently void.
   */
  it('every case exposes a sorobanBinding consistent with its binding', () => {
    for (const c of VECTORS.cases) {
      expect(c.sorobanBinding.subject).toBe(c.binding.walletAddress);
      expect(c.sorobanBinding.contract).toBe(c.binding.contractId);
      expect(c.sorobanBinding.nonceHex).toBe(c.binding.nonce);
      expect(c.sorobanBinding.ledgerExpiry).toBe(c.binding.ledgerExpiry);
      expect(c.sorobanBinding.networkId).toBe(
        toHex(sha256(new TextEncoder().encode(c.binding.networkPassphrase))),
      );
    }
  });

  /**
   * The freshness window `kyc-gate.attest_bbs` will accept. A fixture bound further ahead than
   * `PROOF_MAX_WINDOW` from the ledger the Rust suite attests at (`START_SEQ = 1_000`) is
   * refused on chain with `ExpiryTooFar` before any crypto runs — the vectors would be
   * unusable, and the tombstone/freshness interlock untested. `gate-onramp` sits exactly ON the
   * boundary on purpose.
   */
  it('the frozen bindings sit inside the on-chain proof-freshness window', () => {
    const RUST_TEST_START_SEQ = 1_000;
    const gateOnramp = VECTORS.cases.find((c) => c.name === 'gate-onramp');
    expect(gateOnramp?.binding.ledgerExpiry).toBe(RUST_TEST_START_SEQ + PROOF_MAX_WINDOW);
    for (const c of VECTORS.cases) {
      expect(c.binding.ledgerExpiry - RUST_TEST_START_SEQ).toBeLessThanOrEqual(PROOF_MAX_WINDOW);
    }
  });
});

describe('vectors.json — positive cases', () => {
  const pk = (): Uint8Array => hex(VECTORS.issuer.publicKey.compressed);

  for (const c of VECTORS.cases) {
    it(`verifies "${c.name}" (R=${c.disclosedIndexes.length}, U=${c.undisclosedCount})`, async () => {
      const proof = deserializeProof({
        schemaVersion: SCHEMA_VERSION,
        proof: c.proof.compressed,
        disclosedIndexes: c.disclosedIndexes,
        disclosedMessages: c.disclosedMessages,
        totalMessages: SCHEMA_ATTRIBUTE_COUNT,
        binding: c.binding,
      });
      // No currentLedger: the expired-bound case is cryptographically valid by design.
      expect(await verify(proof, pk(), c.binding, UNSAFE_NO_CHECKS)).toBe(c.expect.verify);
    });

    it(`"${c.name}" obeys the size law and decomposes correctly`, () => {
      const bytes = hex(c.proof.compressed);
      expect(bytes.length).toBe(c.proof.length);
      expect(bytes.length).toBe(expectedProofBytes(c.undisclosedCount));
      expect(c.undisclosedCount).toBe(SCHEMA_ATTRIBUTE_COUNT - c.disclosedIndexes.length);

      const sp = splitProof(bytes);
      expect(toHex(sp.abar)).toBe(c.soroban.abar);
      expect(toHex(sp.bbar)).toBe(c.soroban.bbar);
      expect(toHex(sp.d)).toBe(c.soroban.d);
      expect(toHex(sp.eHat)).toBe(c.soroban.eHat);
      expect(toHex(sp.r1Hat)).toBe(c.soroban.r1Hat);
      expect(toHex(sp.r3Hat)).toBe(c.soroban.r3Hat);
      expect(sp.mHat.map(toHex)).toEqual(c.soroban.mHat);
      expect(toHex(sp.challenge)).toBe(c.soroban.challenge);

      const flat = flattenSorobanProof(sp);
      expect(toHex(flat)).toBe(c.soroban.flat);
      expect(flat.length).toBe(c.soroban.flatLength);
      expect(flat.length).toBe(288 + 32 * (4 + c.undisclosedCount));
    });
  }

  it('covers the empty and full disclosure extremes', () => {
    const names = VECTORS.cases.map((c) => c.name);
    expect(names).toContain('empty-disclosure');
    expect(names).toContain('full-disclosure');
    expect(VECTORS.cases.find((c) => c.name === 'full-disclosure')?.proof.length).toBe(272);
  });
});

describe('vectors.json — negative cases all fail closed', () => {
  const caseByName = (name: string): VectorCase => {
    const c = VECTORS.cases.find((x) => x.name === name);
    if (c === undefined) throw new Error(`no base case ${name}`);
    return c;
  };

  for (const n of VECTORS.negative) {
    it(`rejects "${n.name}"`, async () => {
      const base = caseByName(n.basedOn);
      const binding = n.binding ?? base.binding;
      const proof = deserializeProof({
        schemaVersion: SCHEMA_VERSION,
        proof: n.proof?.compressed ?? base.proof.compressed,
        disclosedIndexes: n.disclosedIndexes ?? base.disclosedIndexes,
        disclosedMessages: n.disclosedMessages ?? base.disclosedMessages,
        totalMessages: SCHEMA_ATTRIBUTE_COUNT,
        // The struct's SELF-DECLARED binding. `'target'` is the attacker who rewrote it to match
        // what the verifier will demand, so the digest compare cannot answer and the rejection
        // must come from the BBS+ math itself.
        binding: n.declaredBinding === 'target' ? binding : base.binding,
      });
      const publicKey = hex(n.publicKey?.compressed ?? VECTORS.issuer.publicKey.compressed);
      const r = await verifyDetailed(proof, publicKey, binding, UNSAFE_NO_CHECKS);
      expect(r.valid).toBe(false);
      expect(n.expect.verify).toBe(false);

      // made every negative case die at the first structural check would stay green while the
      // cryptography stopped being exercised at all — and the Rust verifier, which is coded
      // against these same cases, would be coded against a lie.
      expect(REASONS, `${n.name}: "${n.expect.reason}" is not a VerifyFailure member`).toContain(
        n.expect.reason,
      );
      expect(r.reason, `${n.name}: detail was "${r.detail ?? ''}"`).toBe(n.expect.reason);
    });
  }

  it('every negative case declares ONE real VerifyFailure, never an alternation', () => {
    for (const n of VECTORS.negative) {
      expect(typeof n.expect.reason, n.name).toBe('string');
      expect(n.expect.reason.length, n.name).toBeGreaterThan(0);
      expect(REASONS, n.name).toContain(n.expect.reason);
    }
    // NO alternations. `tampered-abar` carried `bbs-invalid|malformed-proof` for one commit on
    // the grounds that a flipped bit in a compressed point could plausibly die at either door.
    // Both are plausible in general; neither is undetermined HERE, because the proof bytes in
    // this file are frozen, so the outcome is a constant. An alternation would let a genuine
    // behaviour change (say `@noble` returning false where it used to throw) pass unnoticed —
    expect(VECTORS.negative.filter((n) => n.expect.reason.includes('|')).map((n) => n.name)).toEqual(
      [],
    );
  });

  it('pins the replay attacks by the CRYPTOGRAPHY, not only by the struct compare', () => {
    // binding digest compare, ~15 lines into verifyDetailed and long before ProofVerify — so as
    // written they demonstrate that two structs differ, not that a replayed proof fails to
    // verify. A Rust verifier has no self-declared binding and cannot produce
    // `binding-mismatch`, so at least one case must reach the math and say so.
    const byName = new Map(VECTORS.negative.map((n) => [n.name, n]));
    const rewritten = byName.get('wrong-wallet-rewritten-binding');
    expect(rewritten, 'the rewritten-binding sibling of wrong-wallet must exist').toBeDefined();
    expect(rewritten?.declaredBinding).toBe('target');
    expect(rewritten?.expect.reason).toBe('bbs-invalid');
    // And the structural siblings stay structural, deliberately: both doors are pinned.
    for (const name of ['wrong-nonce', 'wrong-contract', 'wrong-wallet']) {
      expect(byName.get(name)?.expect.reason, name).toBe('binding-mismatch');
      expect(byName.get(name)?.declaredBinding, name).toBeUndefined();
    }
  });

  it('includes the attacks the Rust verifier must also reject', () => {
    const names = VECTORS.negative.map((n) => n.name);
    for (const required of [
      'tampered-challenge',
      'tampered-abar',
      'tampered-mhat0',
      'wrong-issuer-key',
      'wrong-nonce',
      'wrong-contract',
      // Without this entry a regression in canonicalBindingBytes's wallet field would only be
      // caught on the Rust side.
      'wrong-wallet',
      'swapped-disclosed-messages',
      'claims-undisclosed-index',
    ]) {
      expect(names).toContain(required);
    }
  });
});
