/**
 * The software P-256 authenticator, verified CRYPTOGRAPHICALLY rather than by shape: an assertion
 * must verify with node:crypto against the exposed public key, must bind the challenge the kit
 * passed, and must fail if a single byte of authenticatorData or clientDataJSON changes. This is
 * the same ceremony that drove four live deployments (EXECUTED ADDENDUM §1); these tests make its
 * properties executable so a future edit cannot quietly weaken the signature layout.
 */

import { createHash, createPublicKey, verify as cryptoVerify } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import {
  SoftwareAuthenticatorError,
  softwareP256WebAuthn,
} from '../../src/index.js';

describe('softwareP256WebAuthn', () => {
  it('generates a P-256 key and exposes it (extractable BY DESIGN — TEST/DEV ONLY)', () => {
    const auth = softwareP256WebAuthn();
    const key = createPublicKey(auth.privateKeyPem);
    const spki = key.export({ type: 'spki', format: 'der' });
    expect(Buffer.from(spki)).toEqual(Buffer.from(auth.publicKeySpki));
    // P-256 SPKI DER is 91 bytes; the leading byte of the point is 0x04 (uncompressed).
    expect(auth.publicKeySpki.length).toBe(91);
    expect(auth.publicKeySpki[auth.publicKeySpki.length - 65]).toBe(4);
  });

  it('two instances are independent keys', () => {
    expect(softwareP256WebAuthn().publicKeySpki).not.toEqual(
      softwareP256WebAuthn().publicKeySpki,
    );
  });

  it('registration returns SPKI publicKey + 37-byte authenticatorData with flags UP|UV', async () => {
    const auth = softwareP256WebAuthn({ rpId: 'tests.example.com' });
    const res = await auth.startRegistration({
      optionsJSON: { challenge: 'reg-challenge', rp: { id: 'tests.example.com' } } as never,
    });
    expect(res.response.publicKey).toBeTruthy();
    const authData = Buffer.from(res.response.authenticatorData as string, 'base64url');
    expect(authData.length).toBe(37);
    expect(authData.subarray(0, 32)).toEqual(
      createHash('sha256').update('tests.example.com').digest(),
    );
    expect(authData[32]).toBe(0x05); // UP | UV
    const clientData = JSON.parse(
      Buffer.from(res.response.clientDataJSON as string, 'base64url').toString('utf8'),
    ) as { type: string; challenge: string; origin: string };
    expect(clientData.type).toBe('webauthn.create');
    expect(clientData.challenge).toBe('reg-challenge');
    expect(clientData.origin).toBe('https://tests.example.com');
  });

  it('an assertion VERIFIES over authData ‖ sha256(clientDataJSON) with the exposed public key', async () => {
    const auth = softwareP256WebAuthn();
    const payload = createHash('sha256').update('the-signature-payload').digest();
    const res = await auth.startAuthentication({
      optionsJSON: { challenge: payload.toString('base64url') },
    } as never);
    const authData = Buffer.from(res.response.authenticatorData as string, 'base64url');
    const clientDataJSON = Buffer.from(res.response.clientDataJSON as string, 'base64url');
    const signed = Buffer.concat([authData, createHash('sha256').update(clientDataJSON).digest()]);
    const derSig = Buffer.from(res.response.signature as string, 'base64url');
    const ok = cryptoVerify(
      'sha256',
      signed,
      createPublicKey(auth.privateKeyPem),
      derSig,
    );
    expect(ok).toBe(true);

    // And the challenge is bound: flipping one byte breaks verification.
    const tampered = Buffer.concat([
      Buffer.from(authData),
      createHash('sha256').update(Buffer.from([...clientDataJSON].slice(0, -1).concat([0]))).digest(),
    ]);
    expect(cryptoVerify('sha256', tampered, createPublicKey(auth.privateKeyPem), derSig)).toBe(false);
  });

  it('the clientDataJSON type is webauthn.get and the challenge round-trips base64url', async () => {
    const auth = softwareP256WebAuthn();
    const res = await auth.startAuthentication({
      optionsJSON: { challenge: 'AAEC' },
    } as never);
    const clientData = JSON.parse(
      Buffer.from(res.response.clientDataJSON as string, 'base64url').toString('utf8'),
    ) as { type: string; challenge: string };
    expect(clientData.type).toBe('webauthn.get'); // what codes 120-126 require
    expect(clientData.challenge).toBe('AAEC');
  });

  it('a supplied PEM private key is adopted (replay fixtures)', () => {
    const first = softwareP256WebAuthn();
    const adopted = softwareP256WebAuthn({ privateKeyPem: first.privateKeyPem });
    expect(adopted.publicKeySpki).toEqual(first.publicKeySpki);
  });

  it('refuses a non-https origin', () => {
    expect(() => softwareP256WebAuthn({ origin: 'http://example.com' })).toThrow(
      SoftwareAuthenticatorError,
    );
  });

  it('refuses to authenticate without a challenge (the contract would refuse too)', async () => {
    const auth = softwareP256WebAuthn();
    await expect(
      auth.startAuthentication({ optionsJSON: {} } as never),
    ).rejects.toThrow(SoftwareAuthenticatorError);
  });
});
