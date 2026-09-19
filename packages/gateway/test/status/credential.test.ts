/**
 * The status list credential ENVELOPE: its canonical form and its Ed25519 signature.
 *
 * THE CRYPTOSUITE IS OURS AND IS NAMED AS SUCH — `stellaronramp-eddsa-jcs-2026`, not
 * `eddsa-jcs-2022`. It is the W3C `eddsa-jcs-2022` construction PLUS a 32-byte domain tag, for the
 * reason the chain side of this repo learned expensively: `attestation_message` and
 * `revocation_message` in contracts/kyc-gate/src/lib.rs carry distinct 32-byte domains precisely so
 * neither can be reinterpreted as the other. The interoperability cost is real and is tested for
 * honestly below rather than glossed.
 */

import { describe, expect, it } from 'vitest';

import {
  BITSTRING_STATUS_LIST_CREDENTIAL_TYPE,
  BITSTRING_STATUS_LIST_TYPE,
  STATUS_LIST_CRYPTOSUITE,
  STATUS_LIST_DOMAIN,
  StatusCredentialError,
  VC_V2_CONTEXT,
  canonicalJson,
  decodeProofValue,
  encodeProofValue,
  parseXsdDateTime,
  signStatusListCredential,
  statusListSigningInput,
  toBitstringStatusList,
  toXsdDateTime,
  verifyStatusListCredential,
} from '../../src/status/credential.js';
import {
  DOCUMENT_ISSUER,
  ISSUER_PUBLIC_KEY,
  ISSUER_SEED,
  OTHER_PUBLIC_KEY,
  OTHER_SEED,
  VERIFICATION_METHOD,
  publish,
} from './fixtures.js';

const EXPECTED = {
  publicKeyRaw: ISSUER_PUBLIC_KEY,
  issuer: DOCUMENT_ISSUER,
  verificationMethod: VERIFICATION_METHOD,
};

describe('the domain tag is exactly 32 bytes, like the chain domains', () => {
  it('is 32 bytes, so it is self-delimiting and needs no length prefix', () => {
    expect(Buffer.from(STATUS_LIST_DOMAIN, 'utf8')).toHaveLength(32);
  });

  it('names OUR cryptosuite, not the plain W3C one, so the divergence is visible on the wire', () => {
    expect(STATUS_LIST_CRYPTOSUITE).toBe('stellaronramp-eddsa-jcs-2026');
    expect(STATUS_LIST_CRYPTOSUITE).not.toBe('eddsa-jcs-2022');
  });

  it('the signing input really begins with the domain tag', async () => {
    const doc = await publish({ revoked: [1] });
    const { proofValue: _v, ...config } = doc.proof!;
    void _v;
    const input = statusListSigningInput(doc, config);
    expect(input.subarray(0, 32)).toEqual(Buffer.from(STATUS_LIST_DOMAIN, 'utf8'));
    // domain(32) + sha256(proofConfig)(32) + sha256(document)(32)
    expect(input).toHaveLength(96);
  });

  it('the signature COMMITS TO the proof config, so a re-labelled proof cannot be replayed', async () => {
    const doc = await publish({ revoked: [1] });
    const { proofValue: _v, ...config } = doc.proof!;
    void _v;
    const base = statusListSigningInput(doc, config);
    for (const field of ['cryptosuite', 'created', 'verificationMethod', 'proofPurpose'] as const) {
      const altered = statusListSigningInput(doc, { ...config, [field]: 'different' });
      expect(altered, `${field} must be committed to`).not.toEqual(base);
    }
  });

  it('the signature commits to the document, so any envelope edit changes the input', async () => {
    const doc = await publish({ revoked: [1] });
    const { proofValue: _v, ...config } = doc.proof!;
    void _v;
    const base = statusListSigningInput(doc, config);
    for (const field of ['id', 'issuer', 'validFrom', 'validUntil'] as const) {
      expect(statusListSigningInput({ ...doc, [field]: 'x' }, config)).not.toEqual(base);
    }
    expect(
      statusListSigningInput(
        { ...doc, credentialSubject: { ...doc.credentialSubject, encodedList: 'uAAAA' } },
        config,
      ),
    ).not.toEqual(base);
  });

  it('IGNORES an existing proof when computing the input, so signing is idempotent', async () => {
    const doc = await publish({ revoked: [1] });
    const { proofValue: _v, ...config } = doc.proof!;
    void _v;
    const withProof = statusListSigningInput(doc, config);
    const { proof: _p, ...unsigned } = doc;
    void _p;
    expect(statusListSigningInput(unsigned as typeof doc, config)).toEqual(withProof);
  });

  it('documents the interoperability COST rather than glossing it', async () => {
    const source = await import('node:fs/promises').then((fs) =>
      fs.readFile(new URL('../../src/status/credential.ts', import.meta.url), 'utf8'),
    );
    expect(source).toContain('a general-purpose W3C VC verifier will NOT verify our proof');
    // And it names the dependency full interop would need, which this run does not add.
    expect(source).toContain('@digitalbazaar/rdf-canonize');
    expect(source).toContain('A NEW DEPENDENCY, and this');
  });
});

describe('canonicalisation is JCS for a RESTRICTED value subset, and refuses the rest', () => {
  it('sorts keys by code unit and emits no whitespace', () => {
    expect(canonicalJson({ b: 1, a: 2 })).toBe('{"a":2,"b":1}');
    expect(canonicalJson({ Z: 1, a: 2, A: 3 })).toBe('{"A":3,"Z":1,"a":2}');
  });

  it('handles the value subset this document actually uses', () => {
    expect(canonicalJson(null)).toBe('null');
    expect(canonicalJson(true)).toBe('true');
    expect(canonicalJson(false)).toBe('false');
    expect(canonicalJson(0)).toBe('0');
    expect(canonicalJson(42)).toBe('42');
    expect(canonicalJson('x')).toBe('"x"');
    expect(canonicalJson([1, 'a', true])).toBe('[1,"a",true]');
    expect(canonicalJson({})).toBe('{}');
    expect(canonicalJson([])).toBe('[]');
  });

  it('omits undefined-valued keys rather than emitting them', () => {
    expect(canonicalJson({ a: 1, b: undefined })).toBe('{"a":1}');
  });

  /**
   * REFUSED LOUDLY, and this is the point. A full JCS implementation must reproduce ECMAScript
   * `Number::toString` exactly for every double. A canonicaliser that is subtly wrong on floats
   * produces a signature that verifies on one runtime and not another. Refusing a float is a
   * build-time surprise; miscanonicalising one is a 3 a.m. surprise.
   */
  it.each([
    ['a float', 1.5],
    ['a negative number', -1],
    ['a number above MAX_SAFE_INTEGER', Number.MAX_SAFE_INTEGER + 2],
    ['NaN', Number.NaN],
    ['Infinity', Number.POSITIVE_INFINITY],
    ['1e21', 1e21],
  ])('refuses %s rather than guessing at its canonical form', (_label, value) => {
    expect(() => canonicalJson({ v: value })).toThrow(StatusCredentialError);
  });

  it.each([
    ['undefined at the top level', undefined],
    ['a function', () => 1],
    ['a symbol', Symbol('x')],
    ['a bigint', 1n],
  ])('refuses %s', (_label, value) => {
    expect(() => canonicalJson(value)).toThrow(StatusCredentialError);
  });

  it('refuses a non-printable-ASCII object key, where hand-rolled JCS diverges', () => {
    expect(() => canonicalJson({ 'é': 1 })).toThrow(StatusCredentialError);
    expect(() => canonicalJson({ '\u{1F600}': 1 })).toThrow(StatusCredentialError);
    expect(() => canonicalJson({ 'a\tb': 1 })).toThrow(StatusCredentialError);
  });

  it('canonicalises -0 as "0", which is what JCS requires (NOT an error)', () => {
    // Number.isInteger(-0) is true and -0 < 0 is false, so -0 is accepted and String(-0) is "0".
    // That is CORRECT: RFC 8785 serialises negative zero as 0. Asserted rather than assumed, because
    // I initially expected this to be refused and it should not be.
    expect(canonicalJson({ v: -0 })).toBe('{"v":0}');
  });

  it('names the offending PATH, so a failure is diagnosable', () => {
    expect(() => canonicalJson({ a: { b: [1.5] } })).toThrow(/\$\.a\.b\[0\]/);
  });

  it('is deterministic: the same object in two key orders canonicalises identically', () => {
    const a = { z: 1, a: { c: 2, b: 3 }, m: [1, 2] };
    const b = { m: [1, 2], a: { b: 3, c: 2 }, z: 1 };
    expect(canonicalJson(a)).toBe(canonicalJson(b));
  });
});

describe('sign and verify are inverses, and verification is PINNED', () => {
  it('a freshly published document verifies against the pinned key', async () => {
    const doc = await publish({ revoked: [1] });
    expect(() => verifyStatusListCredential(doc, EXPECTED)).not.toThrow();
    expect(verifyStatusListCredential(doc, EXPECTED).id).toBe(doc.id);
  });

  it('accepts a PKCS#8 DER key as well as a raw seed, because operators have one or the other', async () => {
    const doc = await publish({ revoked: [1] });
    const { proof: _p, ...unsigned } = doc;
    void _p;
    const pkcs8Der = Buffer.concat([
      Buffer.from('302e020100300506032b657004220420', 'hex'),
      Buffer.from(ISSUER_SEED),
    ]);
    // The proof CONFIG is the proof WITHOUT proofValue. Passing the whole proof object in would
    // canonicalise the old signature into the new signing input and produce a legitimately different
    // result — which is what my first draft of this test did, and is itself a demonstration that the
    // signature commits to its own config.
    const { proofValue: _old, ...config } = doc.proof!;
    void _old;
    const signed = signStatusListCredential(unsigned as typeof doc, { pkcs8Der }, config);
    // Ed25519 is deterministic: same key, same input, byte-identical signature.
    expect(signed.proof?.proofValue).toBe(doc.proof?.proofValue);
    // And it verifies, which is the property an operator actually cares about.
    expect(() => verifyStatusListCredential(signed, EXPECTED)).not.toThrow();
  });

  it('refuses to verify without a pinned 32-byte key, because a document-supplied key is worthless', async () => {
    const doc = await publish({ revoked: [1] });
    for (const publicKeyRaw of [new Uint8Array(31), new Uint8Array(33), new Uint8Array(0)]) {
      expect(() => verifyStatusListCredential(doc, { ...EXPECTED, publicKeyRaw })).toThrow(
        /pinned 32-byte raw Ed25519/,
      );
    }
  });

  it('never reads the key from the document: verificationMethod is a LABEL and is inert', async () => {
    const source = await import('node:fs/promises').then((fs) =>
      fs.readFile(new URL('../../src/status/credential.ts', import.meta.url), 'utf8'),
    );
    const code = source.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/^\s*\/\/.*$/gm, ' ');
    // No fetch, no DID resolution, no key extraction from the document.
    expect(code).not.toMatch(/fetch\s*\(/);
    expect(code).not.toMatch(/resolveDid|didResolver/);
    // The pinned key is the ONLY key material createPublicKey ever sees.
    expect(code).toMatch(/expected\.publicKeyRaw/);
    // And a correctly-signed document from the WRONG issuer is still refused.
    const forged = await publish({ revoked: [], signingKey: { seed: OTHER_SEED } });
    expect(() =>
      verifyStatusListCredential(forged, { ...EXPECTED, publicKeyRaw: OTHER_PUBLIC_KEY }),
    ).not.toThrow();
    expect(() => verifyStatusListCredential(forged, EXPECTED)).toThrow();
  });

  it.each([
    ['not an object', 42],
    ['null', null],
    ['an array', []],
    ['a string', 'x'],
  ])('refuses a document that is %s', (_label, value) => {
    expect(() => verifyStatusListCredential(value, EXPECTED)).toThrow(StatusCredentialError);
  });

  it('refuses a proof of the wrong type', async () => {
    const doc = await publish({ revoked: [1] });
    expect(() =>
      verifyStatusListCredential({ ...doc, proof: { ...doc.proof!, type: 'Ed25519Signature2020' } }, EXPECTED),
    ).toThrow(/only DataIntegrityProof/);
  });

  it('refuses a proof made for authentication being reused as an assertion', async () => {
    const doc = await publish({ revoked: [1] });
    expect(() =>
      verifyStatusListCredential(
        { ...doc, proof: { ...doc.proof!, proofPurpose: 'authentication' } },
        EXPECTED,
      ),
    ).toThrow(/proofPurpose/);
  });

  it('refuses a mismatched verificationMethod when one is expected', async () => {
    const doc = await publish({ revoked: [1], verificationMethod: 'did:web:x#other-key' });
    expect(() => verifyStatusListCredential(doc, EXPECTED)).toThrow(/verificationMethod/);
  });

  it('accepts any verificationMethod when the verifier does not pin one', async () => {
    const doc = await publish({ revoked: [1], verificationMethod: 'did:web:x#other-key' });
    expect(() =>
      verifyStatusListCredential(doc, { publicKeyRaw: ISSUER_PUBLIC_KEY, issuer: DOCUMENT_ISSUER }),
    ).not.toThrow();
  });

  it('refuses a credentialSubject of the wrong type', async () => {
    const doc = await publish({ revoked: [1] });
    expect(() =>
      verifyStatusListCredential(
        { ...doc, credentialSubject: { ...doc.credentialSubject, type: 'SomethingElse' } },
        EXPECTED,
      ),
    ).toThrow(new RegExp(BITSTRING_STATUS_LIST_TYPE));
  });

  it('refuses a document that is not a BitstringStatusListCredential', async () => {
    const doc = await publish({ revoked: [1] });
    expect(() => verifyStatusListCredential({ ...doc, type: ['VerifiableCredential'] }, EXPECTED)).toThrow(
      new RegExp(BITSTRING_STATUS_LIST_CREDENTIAL_TYPE),
    );
  });

  it('refuses a document without the VC v2 context', async () => {
    const doc = await publish({ revoked: [1] });
    expect(() => verifyStatusListCredential({ ...doc, '@context': ['x'] }, EXPECTED)).toThrow(
      new RegExp(VC_V2_CONTEXT.replace(/\//g, '\\/')),
    );
  });

  it('says WHY a missing validUntil matters: a stale mirror could serve it forever', async () => {
    const doc = await publish({ revoked: [1] });
    const stripped = { ...doc } as Record<string, unknown>;
    delete stripped['validUntil'];
    expect(() => verifyStatusListCredential(stripped, EXPECTED)).toThrow(/stale mirror/);
  });
});

describe('the proofValue multibase encoding', () => {
  it('round-trips a 64-byte signature through multibase u', () => {
    const sig = Uint8Array.from({ length: 64 }, (_, i) => i);
    const encoded = encodeProofValue(sig);
    expect(encoded.startsWith('u')).toBe(true);
    expect(decodeProofValue(encoded)).toEqual(sig);
  });

  it.each([
    ['an empty string', ''],
    ['a non-string', 42],
    ['null', null],
    ['the wrong multibase prefix', 'zAAAA'],
    ['base58 prefix', 'z6Mk'],
    ['no prefix at all', 'AAAA'],
  ])('refuses %s', (_label, value) => {
    expect(() => decodeProofValue(value)).toThrow(StatusCredentialError);
  });

  it('refuses a proofValue that does not decode to exactly 64 bytes', () => {
    expect(() => decodeProofValue(encodeProofValue(new Uint8Array(63)))).toThrow(/is 64/);
    expect(() => decodeProofValue(encodeProofValue(new Uint8Array(65)))).toThrow(/is 64/);
  });
});

describe('validFrom / validUntil parsing is UTC and STRICT', () => {
  it('parses a Z-suffixed instant', () => {
    expect(parseXsdDateTime('2026-09-17T12:00:00Z', 'validFrom')).toBe(
      Math.floor(Date.UTC(2026, 8, 17, 12, 0, 0) / 1000),
    );
    expect(parseXsdDateTime('2026-09-17T12:00:00.500Z', 'validFrom')).toBe(
      Math.floor(Date.UTC(2026, 8, 17, 12, 0, 0) / 1000),
    );
  });

  /**
   * `Z`-suffixed ONLY. An offset-bearing or naive form would make the instant depend on how the
   * runtime feels about it, and this value gates whether a revocation list is still trustworthy.
   */
  it.each([
    ['a naive form', '2026-09-17T12:00:00'],
    ['a positive offset', '2026-09-17T12:00:00+02:00'],
    ['a negative offset', '2026-09-17T12:00:00-05:00'],
    ['a space separator', '2026-09-17 12:00:00Z'],
    ['a date only', '2026-09-17'],
    ['a lowercase z', '2026-09-17T12:00:00z'],
    ['an empty string', ''],
    ['garbage', 'soon'],
    ['a number', 1_800_000_000],
    ['null', null],
  ])('refuses %s', (_label, value) => {
    expect(() => parseXsdDateTime(value, 'validFrom')).toThrow(StatusCredentialError);
  });

  it('round-trips through toXsdDateTime', () => {
    for (const unix of [0, 1_800_000_000, 2_000_000_000]) {
      expect(parseXsdDateTime(toXsdDateTime(unix), 'validFrom')).toBe(unix);
    }
  });

  it('emits a Z-suffixed, second-precision form', () => {
    expect(toXsdDateTime(1_800_000_000)).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);
  });

  it.each([-1, 1.5, Number.NaN])('refuses to format %s', (unix) => {
    expect(() => toXsdDateTime(unix)).toThrow(StatusCredentialError);
  });
});

describe('toBitstringStatusList hands identity exactly what its decoder consumes', () => {
  it('projects the credentialSubject, dropping the envelope fields', async () => {
    const doc = await publish({ revoked: [5] });
    const list = toBitstringStatusList(doc);
    expect(Object.keys(list).sort()).toEqual(['encodedList', 'statusPurpose']);
    expect(list.statusPurpose).toBe('revocation');
  });

  it('carries statusSize and statusMessage through when present', async () => {
    const doc = await publish({ revoked: [5], statusSize: 2 });
    const list = toBitstringStatusList(doc);
    expect(list.statusSize).toBe(2);
    expect(Array.isArray(list.statusMessage)).toBe(true);
  });
});
