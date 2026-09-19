/**
 *
 * Every negative case below constructs a token that fails ONLY the property being asserted, so
 * the `reason` the assertion checks is the guard that actually fired — not some earlier structural
 * refusal happening to produce the right status. The classic confusions the brief names get their
 * own cases: `alg:none`, HS256-signed-with-the-public-key, wrong-key, and every missing claim.
 *
 * NO NETWORK, NO WALL CLOCK: the clock is injected (`nowSeconds`) and keys are generated locally.
 */

import { createHmac, createSign, generateKeyPairSync, sign as cryptoSign } from 'node:crypto';
import type { KeyObject } from 'node:crypto';
import { describe, expect, it } from 'vitest';

import {
  ES256,
  JwsError,
  REPLAY_UNCHECKED_NOTE,
  ed25519PublicKeyFromRaw,
  es256PublicKeyFromJwk,
  generateEs256KeyPair,
  signJws,
  verifyJws,
} from '../../src/auth/jws.js';
import type { JsonWebKey } from 'node:crypto';

type SignClaims = Parameters<typeof signJws>[0]['claims'];

/** A minimal jti replay store for the tests: remembers ids until their expiry. */
class InMemoryJtiStore {
  readonly #seen = new Set<string>();
  async firstSight(provider: string, eventId: string, _nowSeconds: number): Promise<boolean> {
    const key = `${provider}\u0000${eventId}`;
    if (this.#seen.has(key)) return false;
    this.#seen.add(key);
    return true;
  }
}

const NOW = 1_700_000_000;
const ISSUER = 'https://issuer.example';
const AUDIENCE = 'gateway-session';

/** The frozen protected header, computed INDEPENDENTLY here so a drift in the library is caught. */
const HEADER_B64 = Buffer.from('{"alg":"ES256","typ":"JWT"}', 'utf8').toString('base64url');

const { privateKey, publicKey } = generateEs256KeyPair();

function baseClaims(over: Partial<Record<string, unknown>> = {}): SignClaims {
  return {
    iss: ISSUER,
    sub: 'GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF',
    aud: AUDIENCE,
    iat: NOW - 60,
    nbf: NOW - 60,
    exp: NOW + 840,
    ...over,
  } as SignClaims;
}

/**
 * Test-side DER -> r‖s compaction, written independently of the library's (a shared buggy
 * implementation would agree with itself all day). Only used to build fixture tokens.
 */
function toRawSig(der: Buffer): Buffer {
  let off = 2;
  const halves: Buffer[] = [];
  for (let i = 0; i < 2; i += 1) {
    const intLen = der[off + 1] as number;
    let start = off + 2;
    const end = start + intLen;
    while (start < end - 1 && der[start] === 0x00) start += 1;
    halves.push(der.subarray(start, end));
    off = end;
  }
  const r = halves[0] as Buffer;
  const s = halves[1] as Buffer;
  const out = Buffer.alloc(64);
  r.copy(out, 32 - r.length);
  s.copy(out, 64 - s.length);
  return out;
}

/** Sign arbitrary header+payload objects with a real ES256 key, emitting a compact JWS. */
function craft(headerObj: object, payloadObj: object | string, key: KeyObject = privateKey): string {
  const h = Buffer.from(JSON.stringify(headerObj), 'utf8').toString('base64url');
  const p =
    typeof payloadObj === 'string'
      ? Buffer.from(payloadObj, 'utf8').toString('base64url')
      : Buffer.from(JSON.stringify(payloadObj), 'utf8').toString('base64url');
  const der = createSign('sha256').update(Buffer.from(`${h}.${p}`, 'ascii')).sign(key);
  return `${h}.${p}.${toRawSig(der).toString('base64url')}`;
}

async function refuse(
  token: string,
  reason: string,
  messagePart?: string,
  overrides: Partial<Parameters<typeof verifyJws>[1]> = {},
): Promise<JwsError> {
  let caught: unknown;
  try {
    await verifyJws(token, { publicKey, nowSeconds: NOW, issuer: ISSUER, audience: AUDIENCE, ...overrides });
  } catch (err) {
    caught = err;
  }
  expect(caught, `expected a JwsError with reason ${reason}`).toBeInstanceOf(JwsError);
  const jwsErr = caught as JwsError;
  // Assert the failure, not merely that something threw: an earlier guard firing means the test
  // is green while the intended defence was never exercised.
  expect(jwsErr.reason, `reason was ${jwsErr.reason}: ${jwsErr.message}`).toBe(reason);
  if (messagePart !== undefined) expect(jwsErr.message).toContain(messagePart);
  return jwsErr;
}

describe('ES256 JWS happy path', () => {
  it('round-trips claims through sign + verify', async () => {
    const token = signJws({ privateKey, claims: baseClaims() });
    const verified = await verifyJws(token, { publicKey, nowSeconds: NOW, issuer: ISSUER, audience: AUDIENCE });
    expect(verified.iss).toBe(ISSUER);
    expect(verified.aud).toBe(AUDIENCE);
    expect(verified.exp).toBe(NOW + 840);
    expect(verified.nbf).toBe(NOW - 60);
    expect(verified.jti).toBeUndefined();
  });

  it('carries exactly the frozen protected header and a 64-byte signature', () => {
    const token = signJws({ privateKey, claims: baseClaims() });
    const [h, , s] = token.split('.');
    expect(h).toBe(HEADER_B64); // {"alg":"ES256","typ":"JWT"}, byte-stable
    expect(Buffer.from(s as string, 'base64url').length).toBe(64); // r‖s, never DER
  });

  it('two signings of one claim set differ in signature bytes (ECDSA random nonce) yet BOTH verify', async () => {
    // ECDSA signatures are randomized (unlike Ed25519); what must be stable is the VERDICT, and
    // the header/payload bytes, never the signature.
    const a = signJws({ privateKey, claims: baseClaims({ jti: 'jti-1' }) });
    const b = signJws({ privateKey, claims: baseClaims({ jti: 'jti-1' }) });
    expect(a.split('.')[0]).toBe(b.split('.')[0]);
    expect(a.split('.')[1]).toBe(b.split('.')[1]);
    for (const token of [a, b]) {
      const verified = await verifyJws(token, { publicKey, nowSeconds: NOW, issuer: ISSUER, audience: AUDIENCE });
      expect(verified.jti).toBe('jti-1');
    }
  });

  it('serializes claims in a fixed order (iss, sub, aud, iat, nbf, exp, jti?)', () => {
    const token = signJws({ privateKey, claims: baseClaims({ jti: 'abc' }) });
    const payload = JSON.parse(Buffer.from(token.split('.')[1] as string, 'base64url').toString('utf8')) as Record<string, unknown>;
    expect(Object.keys(payload)).toEqual(['iss', 'sub', 'aud', 'iat', 'nbf', 'exp', 'jti']);
  });
});

describe('alg confusion (the brief\'s named bug class)', () => {
  it('refuses alg:none even with an empty signature', async () => {
    // Header says none; signature segment empty. Refused at the header, before any signature work.
    const h = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' }), 'utf8').toString('base64url');
    const p = Buffer.from(JSON.stringify(baseClaims()), 'utf8').toString('base64url');
    await refuse(`${h}.${p}.`, 'alg-not-es256', 'alg="none"');
  });

  it('refuses HS256 signed with the PUBLIC key (the classic confusion)', async () => {
    // Export the public key's SPKI bytes and HMAC with them — exactly the attack where the
    // verifier treats its own verification key as an HMAC secret.
    const spki = publicKey.export({ type: 'spki', format: 'der' });
    const h = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' }), 'utf8').toString('base64url');
    const p = Buffer.from(JSON.stringify(baseClaims()), 'utf8').toString('base64url');
    const sig = createHmac('sha256', spki).update(Buffer.from(`${h}.${p}`, 'ascii')).digest();
    const token = `${h}.${p}.${sig.toString('base64url')}`;
    await refuse(token, 'alg-not-es256', 'HS256');
  });

  it('refuses an ES256-labelled token when the KEY is not EC P-256 (pin follows the key)', async () => {
    // A valid-looking ES256 token offered to an Ed25519 verifier: refused before any claim is
    // an Ed25519 KEY is no longer itself a refusal — instead its key-derived algorithm (EdDSA)
    // disagrees with the presented header (ES256), and the reason names the cross-scheme
    // relabelling. A P-384 EC key — right family, wrong curve — remains a plain key-type refusal.
    const token = signJws({ privateKey, claims: baseClaims() });
    const ed = generateKeyPairSync('ed25519');
    await refuse(token, 'alg-not-eddsa', 'ES256', { publicKey: ed.publicKey });
    const p384 = generateKeyPairSync('ec', { namedCurve: 'secp384r1' });
    await refuse(token, 'not-an-ec-p256-key', undefined, { publicKey: p384.publicKey });
  });

  it('refuses an EdDSA-labelled token when the KEY is not OKP Ed25519 (mirror of the ES256 pin)', async () => {
    // Symmetry case added with Ed25519 support: an anchor-style EdDSA token offered to an EC
    // P-256 verifier refuses naming the key-derived alg; a P-384 key refuses as a wrong curve.
    const ed = generateKeyPairSync('ed25519');
    const token = signJws({ privateKey: ed.privateKey, claims: baseClaims() });
    await refuse(token, 'alg-not-es256', 'EdDSA', { publicKey });
    const p384 = generateKeyPairSync('ec', { namedCurve: 'secp384r1' });
    await refuse(token, 'not-an-ec-p256-key', undefined, { publicKey: p384.publicKey });
  });

  it('refuses a header that differs from the frozen one while still claiming ES256', async () => {
    await refuse(craft({ alg: ES256 }, baseClaims()), 'bad-header'); // typ missing
    await refuse(
      craft({ alg: ES256, typ: 'JWT', kid: 'k1' }, baseClaims()),
      'bad-header',
    );
  });

  it('refuses embedded/pointed key material and crit extensions', async () => {
    const jwkHeader = { alg: ES256, typ: 'JWT', jku: 'https://attacker.example/jwks.json' };
    await refuse(craft(jwkHeader, baseClaims()), 'bad-header', 'key material');
    const critHeader = { alg: ES256, typ: 'JWT', crit: ['b64'] };
    await refuse(craft(critHeader, baseClaims()), 'bad-header', 'critical');
  });
});

describe('signature failures', () => {
  it('refuses a token signed by a DIFFERENT P-256 key (wrong-key)', async () => {
    const stranger = generateEs256KeyPair();
    const token = signJws({ privateKey: stranger.privateKey, claims: baseClaims() });
    await refuse(token, 'signature-mismatch');
  });

  it('refuses a tampered signature (single character flip inside the alphabet)', async () => {
    // JWS signature's last base64url char carries only 2 live bits + 4 padding bits — two final
    // characters agreeing in their top 2 bits decode to IDENTICAL bytes, so flipping A->B (or
    // any of A..P -> A/B) was often a NO-OP tamper: nothing threw, and the cell passed while
    // exercising no refusal at all (~25% of runs, seeded by ECDSA randomness). The flip now
    // targets the second-to-last character, whose 6 bits are all live, so the decoded bytes
    // ALWAYS change and signature-mismatch is guaranteed to fire.
    const token = signJws({ privateKey, claims: baseClaims() });
    const parts = token.split('.');
    const last = parts[2] as string;
    expect(last.length).toBe(86); // 64 bytes -> ceil(512/6); the final char is partially padded
    const penult = last.at(-2) as string;
    const flippedPenult =
      penult === 'A'
        ? `${last.slice(0, -2)}B${last.at(-1)}`
        : `${last.slice(0, -2)}A${last.at(-1)}`;
    await refuse([parts[0], parts[1], flippedPenult].join('.'), 'signature-mismatch');

    // The trap itself, pinned on fixed data independent of ECDSA randomness: flipping ONLY the
    // padding bits of a final character does not change the decoded bytes ('A'=000000 vs
    // 'B'=000001 differ below the 2 live bits), which is exactly why the flip moved left.
    const zeros = 'A'.repeat(85);
    expect(Buffer.from(`${zeros}A`, 'base64url').equals(Buffer.from(`${zeros}B`, 'base64url'))).toBe(true);
  });

  it('refuses a tampered PAYLOAD under a valid signature', async () => {
    const token = signJws({ privateKey, claims: baseClaims() });
    const parts = token.split('.');
    const forged = Buffer.from(JSON.stringify(baseClaims({ sub: 'GATTACKER' })), 'utf8').toString('base64url');
    await refuse([parts[0], forged, parts[2]].join('.'), 'signature-mismatch');
  });

  it.each([62, 63, 65, 66])('refuses a %i-byte compact signature (only exactly 64 accepted)', async (n) => {
    const token = signJws({ privateKey, claims: baseClaims() });
    const parts = token.split('.');
    const bad = Buffer.alloc(n, 7).toString('base64url');
    await refuse([parts[0], parts[1], bad].join('.'), 'signature-length', '64');
  });

  it('refuses 31-byte and 33-byte r‖s HALVES (the DER-style mis-split)', async () => {
    // 31+31 and 33+33 byte totals: the specific shapes a naive splitter produces when it trims or
    // over-reads a half. Both are length refusals before any curve arithmetic.
    for (const total of [62, 66]) {
      const token = signJws({ privateKey, claims: baseClaims() });
      const parts = token.split('.');
      const bad = Buffer.alloc(total, 9).toString('base64url');
      await refuse([parts[0], parts[1], bad].join('.'), 'signature-length');
    }
  });

  it('refuses a full DER signature pasted into the compact field', async () => {
    // Build a well-formed 70-byte DER ECDSA-Sig-Value deterministically (two 32-byte INTEGERs,
    // high bits set so they need no padding): SEQUENCE(66) { INT(32), INT(32) } = 70 bytes.
    const r = Buffer.concat([Buffer.from([0xff]), Buffer.alloc(31, 0xaa)]);
    const s = Buffer.concat([Buffer.from([0x7f]), Buffer.alloc(31, 0xbb)]);
    const int1 = Buffer.concat([Buffer.from([0x02, 0x20]), r]);
    const int2 = Buffer.concat([Buffer.from([0x02, 0x20]), s]);
    const body = Buffer.concat([int1, int2]);
    const der = Buffer.concat([Buffer.from([0x30, body.length]), body]);
    expect(der.length).toBe(70);

    const token = signJws({ privateKey, claims: baseClaims() });
    const parts = token.split('.');
    // 70 bytes != 64, so this is a LENGTH refusal naming the compact encoding — the alert says
    // "wrong encoding for a JWS", an integration bug rather than an attack.
    await refuse([parts[0], parts[1], der.toString('base64url')].join('.'), 'signature-length', 'compact');
  });
});

describe('claim checking: NONE defaulted', () => {
  for (const absent of ['iss', 'sub', 'aud', 'iat', 'nbf', 'exp'] as const) {
    it(`refuses a token with "${absent}" missing (both directions; claim-absent names the claim)`, async () => {
      // SIGN side: an issuer cannot mint a claim-less token.
      const claims = { ...baseClaims() } as Record<string, unknown>;
      delete claims[absent];
      expect(() => signJws({ privateKey, claims: claims as unknown as SignClaims })).toThrow(/JwsError|refusing/);
      let signReason = '';
      try {
        signJws({ privateKey, claims: claims as unknown as SignClaims });
      } catch (err) {
        signReason = (err as JwsError).reason;
      }
      expect(signReason).toBe('claim-absent');

      // VERIFY side: a token FORGED to lack the claim (validly signed by a test key so the
      // signature guard does not fire first) is still refused.
      await refuse(craft({ alg: ES256, typ: 'JWT' }, claims), 'claim-absent', `"${absent}"`);
    });
  }

  it('refuses wrong-typed claims', async () => {
    await refuse(craft({ alg: ES256, typ: 'JWT' }, baseClaims({ sub: 42 })), 'claim-type');
    await refuse(craft({ alg: ES256, typ: 'JWT' }, baseClaims({ iss: '' })), 'claim-type');
    await refuse(craft({ alg: ES256, typ: 'JWT' }, baseClaims({ exp: 'later' })), 'claim-type');
    await refuse(craft({ alg: ES256, typ: 'JWT' }, baseClaims({ iat: NOW + 0.5 })), 'claim-type');
    await refuse(craft({ alg: ES256, typ: 'JWT' }, baseClaims({ nbf: null })), 'claim-type');
  });
});

describe('expected-party binding and the injected clock', () => {
  it('refuses a foreign issuer and a foreign audience', async () => {
    const token = signJws({ privateKey, claims: baseClaims() });
    let caught: unknown;
    try {
      await verifyJws(token, { publicKey, nowSeconds: NOW, issuer: 'https://other.example', audience: AUDIENCE });
    } catch (err) {
      caught = err;
    }
    expect((caught as JwsError).reason).toBe('issuer-mismatch');

    try {
      await verifyJws(token, { publicKey, nowSeconds: NOW, issuer: ISSUER, audience: 'other-audience' });
    } catch (err) {
      caught = err;
    }
    expect((caught as JwsError).reason).toBe('audience-mismatch');
  });

  it('refuses an audience in ARRAY form at the type gate (our issuer emits the string form only)', async () => {
    // The RFC-permitted array form is refused as a wrong-typed claim — a documented narrowing,
    // not an audience comparison miss.
    const token = craft({ alg: ES256, typ: 'JWT' }, baseClaims({ aud: [AUDIENCE, 'other'] }));
    await refuse(token, 'claim-type');
  });

  it('refuses a future-nbf token (not yet valid) at the injected now', async () => {
    const token = signJws({ privateKey, claims: baseClaims({ nbf: NOW + 600 }) });
    await refuse(token, 'token-not-yet-valid');
  });

  it('refuses an expired token (exp == now counts as expired)', async () => {
    await refuse(signJws({ privateKey, claims: baseClaims({ exp: NOW }) }), 'token-expired');
    await refuse(signJws({ privateKey, claims: baseClaims({ exp: NOW - 1 }) }), 'token-expired');
  });

  it('accepts a token inside its window (nbf <= now < exp)', async () => {
    const token = signJws({ privateKey, claims: baseClaims({ nbf: NOW, exp: NOW + 1 }) });
    const verified = await verifyJws(token, { publicKey, nowSeconds: NOW, issuer: ISSUER, audience: AUDIENCE });
    expect(verified.sub).toBe(baseClaims()['sub']);
  });

  it('handles signatures whose r or s half begins with a zero byte (scalar < 2^248)', async () => {
    // Regression: a fixed-width half legitimately starts 0x00 about 1/256 of the time per half;
    // an earlier rawToDer draft refused those outright. Two probes:
    //   (a) deterministic — a CRAFTED 64-byte signature with a leading-zero half must reach the
    //       verifier (signature-mismatch), never die in the DER encoder (signature-length);
    const token = signJws({ privateKey, claims: baseClaims() });
    const parts = token.split('.');
    const craftedHalfZero = Buffer.concat([Buffer.alloc(1, 0x00), Buffer.alloc(63, 0x11)]);
    await refuse([parts[0], parts[1], craftedHalfZero.toString('base64url')].join('.'), 'signature-mismatch');
    //   (b) probabilistic — sign until a REAL signature exhibits the shape, and confirm it
    //       round-trips. P(half starts 0x00) ≈ 1/256, so 4000 signings make failure astronomically
    //       unlikely (~e^-31) without being a hard bound.
    let found = false;
    for (let i = 0; i < 4000 && !found; i += 1) {
      const t = signJws({ privateKey, claims: baseClaims() });
      const raw = Buffer.from(t.split('.')[2] as string, 'base64url');
      if (raw[0] === 0x00 || raw[32] === 0x00) {
        found = true;
        const verified = await verifyJws(t, { publicKey, nowSeconds: NOW, issuer: ISSUER, audience: AUDIENCE });
        expect(verified.exp).toBe(NOW + 840);
      }
    }
    expect(found, 'no leading-zero-half signature observed in 4000 signings').toBe(true);
  }, 30_000);
});

describe('structural strictness', () => {
  it('refuses wrong segment counts', async () => {
    const token = signJws({ privateKey, claims: baseClaims() });
    await refuse(token.split('.').slice(0, 2).join('.'), 'malformed-token');
    await refuse(`${token}.extra`, 'malformed-token');
  });

  it('refuses padded / foreign-alphabet base64url segments', async () => {
    const token = signJws({ privateKey, claims: baseClaims() });
    const parts = token.split('.');
    await refuse([parts[0], parts[1], `${parts[2]}=`].join('.'), 'malformed-token');
    await refuse([`${parts[0] as string}!`, parts[1], parts[2]].join('.'), 'malformed-token');
  });

  it('refuses a non-JSON or non-object payload under a VALID signature', async () => {
    await refuse(craft({ alg: ES256, typ: 'JWT' }, '"just a string"'), 'payload-malformed');
    await refuse(craft({ alg: ES256, typ: 'JWT' }, '[1,2,3]'), 'payload-malformed');
    const h = HEADER_B64;
    const p = Buffer.from('{not json', 'utf8').toString('base64url');
    const der = createSign('sha256').update(Buffer.from(`${h}.${p}`, 'ascii')).sign(privateKey);
    await refuse(`${h}.${p}.${toRawSig(der).toString('base64url')}`, 'payload-malformed');
  });
});

describe('jti replay hook', () => {
  it('is NOT replay-checked when the hook is unconfigured (documented absence)', async () => {
    // The note exists to be asserted on (the NO_IP_ALLOWLIST pattern): the absence must not be
    // able to regress quietly into silence.
    expect(REPLAY_UNCHECKED_NOTE).toContain('NOT replay-checked');
    const token = signJws({ privateKey, claims: baseClaims() }); // no jti at all
    const verified = await verifyJws(token, { publicKey, nowSeconds: NOW, issuer: ISSUER, audience: AUDIENCE });
    expect(verified.jti).toBeUndefined();
  });

  it('REQUIRES jti once a store is configured (no silent exemption for jti-less tokens)', async () => {
    const token = signJws({ privateKey, claims: baseClaims() }); // no jti at all
    await refuse(token, 'claim-absent', 'replay store is configured', {
      replay: { store: new InMemoryJtiStore(), provider: 'session-jwt' },
    });
  });

  it('detects a replayed jti through the atomic first-sight store', async () => {
    // The webhook dedupe store plugs in UNCHANGED — structural compatibility is the point.
    const store = new InMemoryJtiStore();
    const opts = { replay: { store, provider: 'session-jwt' } };
    const first = await verifyJws(signJws({ privateKey, claims: baseClaims({ jti: 'same-jti' }) }), {
      publicKey, nowSeconds: NOW, issuer: ISSUER, audience: AUDIENCE, ...opts,
    });
    expect(first.jti).toBe('same-jti');
    // A SECOND, differently-signed token carrying the SAME jti is a replay.
    const second = signJws({ privateKey, claims: baseClaims({ jti: 'same-jti', exp: NOW + 900 }) });
    await refuse(second, 'replay-detected', 'already been seen', opts);
  });
});

describe('sign-side discipline', () => {
  it('refuses to SIGN with a wrong-family key; Ed25519 signs under its own pinned header', () => {
    // an EdDSA-headered token (verified below by the matching Ed25519 verifier). What is STILL
    // refused before any bytes are signed: a key from neither supported family, and a
    // right-family/wrong-curve EC key.
    const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 });
    expect(() => signJws({ privateKey: rsa.privateKey, claims: baseClaims() })).toThrow(JwsError);
    let reason = '';
    try {
      signJws({ privateKey: rsa.privateKey, claims: baseClaims() });
    } catch (err) {
      reason = (err as JwsError).reason;
    }
    expect(reason).toBe('not-an-ec-p256-key');

    const p384 = generateKeyPairSync('ec', { namedCurve: 'secp384r1' });
    expect(() => signJws({ privateKey: p384.privateKey, claims: baseClaims() })).toThrow(/curve/);

    const ed = generateKeyPairSync('ed25519');
    const token = signJws({ privateKey: ed.privateKey, claims: baseClaims() });
    const header = JSON.parse(Buffer.from(token.split('.')[0] as string, 'base64url').toString('utf8')) as Record<string, unknown>;
    expect(header['alg']).toBe('EdDSA'); // frozen per-alg header, never caller-chosen
    expect(header['typ']).toBe('JWT');
  });

  it('refuses inverted validity windows', () => {
    expect(() => signJws({ privateKey, claims: baseClaims({ nbf: NOW + 10, exp: NOW + 10 }) })).toThrow(/inverted/);
  });

  it('refuses unregistered claims (no accidental PII into a signed token)', () => {
    const sneaky = baseClaims({ email: 'subject@example.com' }) as unknown as SignClaims;
    expect(() => signJws({ privateKey, claims: sneaky })).toThrow(/unregistered claim "email"/);
  });

  it('refuses absent required claims at SIGN time too', () => {
    const partial = { iss: ISSUER, sub: 'GX', aud: AUDIENCE, iat: NOW, nbf: NOW } as unknown as Parameters<typeof signJws>[0]['claims'];
    expect(() => signJws({ privateKey, claims: partial })).toThrow(/"exp"/);
  });
});

describe('JWK key construction', () => {
  it('builds a verifying KeyObject from the public JWK and refuses a wrong-curve JWK', async () => {
    const jwk = publicKey.export({ format: 'jwk' }) as JsonWebKey;
    const rebuilt = es256PublicKeyFromJwk(jwk);
    const token = signJws({ privateKey, claims: baseClaims() });
    const verified = await verifyJws(token, { publicKey: rebuilt, nowSeconds: NOW, issuer: ISSUER, audience: AUDIENCE });
    expect(verified.iss).toBe(ISSUER);

    const p384 = generateKeyPairSync('ec', { namedCurve: 'secp384r1' });
    const wrong = p384.publicKey.export({ format: 'jwk' }) as JsonWebKey;
    expect(() => es256PublicKeyFromJwk(wrong)).toThrow(/P-256/);
  });
});

/**
 * verifies. Same pinning discipline as the ES256 block above, exercised on the second scheme:
 * alg from KEY TYPE, frozen per-alg header, exactly-64-byte signatures, claims-none-defaulted.
 */
describe('EdDSA (SEP-10 anchor tokens)', () => {
  const ed = generateKeyPairSync('ed25519');
  /** Raw 32-byte form, the shape an anchor's key takes in config (Stellar account key encoding). */
  const edRaw = new Uint8Array(ed.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32));
  const edVerifier = ed25519PublicKeyFromRaw(edRaw);

  it('round-trips an anchor-style token through the raw-bytes verifier', async () => {
    const token = signJws({ privateKey: ed.privateKey, claims: baseClaims() });
    const verified = await verifyJws(token, { publicKey: edVerifier, nowSeconds: NOW, issuer: ISSUER, audience: AUDIENCE });
    expect(verified.sub).toBe('GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF');
  });

  it('carries the frozen {"alg":"EdDSA","typ":"JWT"} header and is byte-deterministic', () => {
    // Ed25519 is deterministic (RFC 8032): unlike ES256 above, two signings of one claim set
    // produce IDENTICAL tokens — pinned here so a future refactor that breaks that property
    // surfaces as a loud diff.
    const a = signJws({ privateKey: ed.privateKey, claims: baseClaims() });
    const b = signJws({ privateKey: ed.privateKey, claims: baseClaims() });
    expect(a).toBe(b);
    expect(a.split('.')[0]).toBe(
      Buffer.from('{"alg":"EdDSA","typ":"JWT"}', 'utf8').toString('base64url'),
    );
  });

  it('refuses a foreign Ed25519 key with signature-mismatch', async () => {
    const stranger = generateKeyPairSync('ed25519');
    const token = signJws({ privateKey: stranger.privateKey, claims: baseClaims() });
    await refuse(token, 'signature-mismatch', undefined, { publicKey: edVerifier });
  });

  it('refuses a tampered payload under a valid EdDSA signature', async () => {
    const token = signJws({ privateKey: ed.privateKey, claims: baseClaims() });
    const parts = token.split('.');
    const forged = Buffer.from(JSON.stringify(baseClaims({ sub: 'GATTACKER' })), 'utf8').toString('base64url');
    await refuse([parts[0], forged, parts[2]].join('.'), 'signature-mismatch', undefined, { publicKey: edVerifier });
  });

  it.each([63, 65])('refuses a %i-byte EdDSA signature (only exactly 64 accepted)', async (n) => {
    const token = signJws({ privateKey: ed.privateKey, claims: baseClaims() });
    const parts = token.split('.');
    const bad = Buffer.alloc(n, 7).toString('base64url');
    await refuse([parts[0], parts[1], bad].join('.'), 'signature-length', 'Ed25519 R then S', { publicKey: edVerifier });
  });

  it('refuses a DER-encoded ECDSA signature pasted into the compact field', async () => {
    // A DER ECDSA sig is ~70-72 bytes — exactly what the length gate refuses BEFORE any parse.
    // (The same discipline the ES256 side pins.) Any 71-byte blob stands in for the encoding;
    // the point is the length, not the contents.
    const token = signJws({ privateKey: ed.privateKey, claims: baseClaims() });
    const parts = token.split('.');
    const fakeDer = Buffer.alloc(71, 0x30);
    await refuse([parts[0], parts[1], fakeDer.toString('base64url')].join('.'), 'signature-length', '64', { publicKey: edVerifier });
  });

  it('keeps claims discipline identical on the EdDSA path (absent exp, foreign issuer)', async () => {
    // signJws validates claims BEFORE signing, so an exp-less token must be crafted directly to
    // reach the verifier — the same construction the alg-confusion cells use on the ES256 side.
    // Signed by THIS describe's key so the signature clears and the claim gate is what fires.
    const craftEd = (payloadObj: object): string => {
      const h = Buffer.from('{"alg":"EdDSA","typ":"JWT"}', 'utf8').toString('base64url');
      const p = Buffer.from(JSON.stringify(payloadObj), 'utf8').toString('base64url');
      const sig = cryptoSign(null, Buffer.from(`${h}.${p}`, 'ascii'), ed.privateKey);
      return `${h}.${p}.${sig.toString('base64url')}`;
    };
    const noExp = { iss: ISSUER, sub: 'GX', aud: AUDIENCE, iat: NOW, nbf: NOW };
    await refuse(craftEd(noExp), 'claim-absent', '"exp"', { publicKey: edVerifier });
    const t2 = signJws({ privateKey: ed.privateKey, claims: baseClaims({ iss: 'https://elsewhere.example' }) });
    await refuse(t2, 'issuer-mismatch', undefined, { publicKey: edVerifier });
  });

  it('ed25519PublicKeyFromRaw refuses 31 and 33 bytes and accepts exactly 32', () => {
    expect(() => ed25519PublicKeyFromRaw(new Uint8Array(31))).toThrow(RangeError);
    expect(() => ed25519PublicKeyFromRaw(new Uint8Array(33))).toThrow(RangeError);
    expect(() => ed25519PublicKeyFromRaw(edRaw)).not.toThrow();
  });
});

/**
 * {iss, sub, iat, exp[, jti]} — aud only in the client-domain flow, nbf not at all — so requiring
 * them fixed-401'd exactly the credentials the SEP-12 surface exists to accept. Under the policy
 * they become OPTIONAL-but-enforced-when-present; everything else stays strict. Each negative
 * case fails ONLY the property asserted, as everywhere above.
 */
describe('SEP-10 claim policy', () => {
  const ed = generateKeyPairSync('ed25519');
  const edVerifier = ed25519PublicKeyFromRaw(
    new Uint8Array(ed.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32)),
    );
  /** Craft an EdDSA token from an ARBITRARY payload object (signJws would demand all claims). */
  const craftEd = (payloadObj: Record<string, unknown>): string => {
    const h = Buffer.from('{"alg":"EdDSA","typ":"JWT"}', 'utf8').toString('base64url');
    const p = Buffer.from(JSON.stringify(payloadObj), 'utf8').toString('base64url');
    const sig = cryptoSign(null, Buffer.from(`${h}.${p}`, 'ascii'), ed.privateKey);
    return `${h}.${p}.${sig.toString('base64url')}`;
  };
  /** Canonical shape per SEP-10: no aud, no nbf, jti present. */
  const canonical = {
    iss: ISSUER,
    sub: 'GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF',
    iat: NOW - 30,
    exp: NOW + 870,
    jti: 'sep10-canonical',
  };
  const verifyOpts = { publicKey: edVerifier, issuer: ISSUER, audience: AUDIENCE };

  it('accepts a CANONICAL anchor token ({iss, sub, iat, exp, jti}) and omits the absent claims from the result', async () => {
    const verified = await verifyJws(craftEd(canonical), { ...verifyOpts, nowSeconds: NOW, claimPolicy: 'sep10' });
    expect(verified.sub).toBe(canonical.sub);
    expect(verified.jti).toBe('sep10-canonical');
    expect(verified.aud).toBeUndefined();
    expect(verified.nbf).toBeUndefined();
  });

  it('STILL refuses missing iss/sub/iat/exp under the sep10 policy (relaxation is aud/nbf only)', async () => {
    for (const absent of ['iss', 'sub', 'iat', 'exp'] as const) {
      const payload = { ...canonical };
      delete payload[absent];
      await refuse(craftEd(payload), 'claim-absent', `"${absent}"`, {
        ...verifyOpts,
        nowSeconds: NOW,
        claimPolicy: 'sep10',
    });
    }
  });

  it('a PRESENT aud must still equal the pinned expectation, exactly as under strict', async () => {
    const right = await verifyJws(craftEd({ ...canonical, aud: AUDIENCE }), {
      ...verifyOpts, nowSeconds: NOW, claimPolicy: 'sep10',
    });
    expect(right.aud).toBe(AUDIENCE);
    await refuse(craftEd({ ...canonical, aud: 'someone-elses-surface' }), 'audience-mismatch', undefined, {
      ...verifyOpts,
      nowSeconds: NOW,
      claimPolicy: 'sep10',
    });
  });

  it('a PRESENT nbf still gates the window; an absent one does not block anything', async () => {
    await refuse(craftEd({ ...canonical, nbf: NOW + 600 }), 'token-not-yet-valid', undefined, {
      ...verifyOpts,
      nowSeconds: NOW,
      claimPolicy: 'sep10',
    });
    const ok = await verifyJws(craftEd({ ...canonical, nbf: NOW - 30 }), {
      ...verifyOpts, nowSeconds: NOW, claimPolicy: 'sep10',
    });
    expect(ok.nbf).toBe(NOW - 30);
  });

  it('wrong-typed PRESENT aud/nbf are refused under the sep10 policy (presence keeps every discipline)', async () => {
    await refuse(craftEd({ ...canonical, aud: ['array-form'] }), 'claim-type', undefined, {
      ...verifyOpts,
      nowSeconds: NOW,
      claimPolicy: 'sep10',
    });
    await refuse(craftEd({ ...canonical, nbf: 'long ago' }), 'claim-type', undefined, {
      ...verifyOpts,
      nowSeconds: NOW,
      claimPolicy: 'sep10',
    });
  });

  it('the DEFAULT policy is unchanged: a canonical (aud/nbf-less) token is still refused there', async () => {
    // Session-JWT verification never passes claimPolicy, so its discipline must be byte-identical
    // to before this option existed.
    await refuse(craftEd(canonical), 'claim-absent', '"aud"', { ...verifyOpts, nowSeconds: NOW });
  });
});
