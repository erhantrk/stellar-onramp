/**
 * `Es256SessionJwtIssuer` — the REAL session-JWT issuer behind the fail-closed seam.
 *
 * The token it mints is checked with the LIBRARY's independent verifier (`verifyJws`), not by
 * re-reading the issuer's own assumptions — same discipline as signing a webhook body with the
 * code that verifies one: the round trip must go through BOTH halves.
 *
 * NO NETWORK. Keys are generated locally; the clock is injected.
 */

import { generateKeyPairSync } from 'node:crypto';
import { describe, expect, it } from 'vitest';

import { verifyJws } from '@stellaronramp/gateway';

import {
  Es256SessionJwtIssuer,
  SESSION_JWT_MAX_TTL_SECONDS,
  UnimplementedSessionJwtIssuer,
} from '../src/seams/session-jwt.js';

const NOW = 1_700_000_000;
const ISSUER = 'https://gateway.example';
const AUDIENCE = 'gateway-session';
const WALLET_C = 'CAQNEGTJ7B4KABCDJKXKGV6NJKMPJV3YHUFBRBSPLBNJDGGFEK5AA2LT'; // shape only
const SESSION_ID = '018ee1c8-f2e7-7cc8-b63d-9f3f0e34bdc6';

function makeIssuer() {
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  return new Es256SessionJwtIssuer({ signingKey: privateKey, issuer: ISSUER, audience: AUDIENCE });
}

describe('Es256SessionJwtIssuer', () => {
  it('mints an ES256 token that the library verifier accepts with sub = wallet C-address', async () => {
    const issuer = makeIssuer();
    const token = await issuer.issue({
      sessionId: SESSION_ID,
      walletCAddr: WALLET_C,
      issuedAt: NOW,
      expiresAt: NOW + SESSION_JWT_MAX_TTL_SECONDS,
    });
    const verified = await verifyJws(token, {
      publicKey: issuer.verificationKey,
      nowSeconds: NOW + 60,
      issuer: ISSUER,
      audience: AUDIENCE,
    });
    expect(verified.sub).toBe(WALLET_C);
    expect(verified.exp - verified.iat).toBe(SESSION_JWT_MAX_TTL_SECONDS);
    expect(verified.iss).toBe(ISSUER);
    expect(verified.aud).toBe(AUDIENCE);
  });

  it('refuses a TTL beyond the schema’s 15 minutes (the cap is enforced, not advisory)', async () => {
    const issuer = makeIssuer();
    let message = '';
    try {
      await issuer.issue({
        sessionId: SESSION_ID,
        walletCAddr: WALLET_C,
        issuedAt: NOW,
        expiresAt: NOW + 3600, // the old hard-coded value
      });
    } catch (err) {
      message = String((err as Error).message);
    }
    expect(message).toContain('15 min');
  });

  it('refuses a non-positive validity window', async () => {
    const issuer = makeIssuer();
    await expect(
      issuer.issue({ sessionId: SESSION_ID, walletCAddr: WALLET_C, issuedAt: NOW, expiresAt: NOW }),
    ).rejects.toThrow(/not positive/);
  });

  it('refuses construction without an explicit issuer or audience (no defaults to forget)', () => {
    const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    expect(
      () => new Es256SessionJwtIssuer({ signingKey: privateKey, issuer: '', audience: AUDIENCE }),
    ).toThrow(/issuer and audience/);
  });

  it('a foreign audience cannot consume the token, and vice versa (audience-scoped)', async () => {
    const issuer = makeIssuer();
    const token = await issuer.issue({
      sessionId: SESSION_ID,
      walletCAddr: WALLET_C,
      issuedAt: NOW,
      expiresAt: NOW + 600,
    });
    await expect(
      verifyJws(token, {
        publicKey: issuer.verificationKey,
        nowSeconds: NOW,
        issuer: ISSUER,
        audience: 'other-surface',
      }),
    ).rejects.toThrow(/audience/);
  });

  it('the DEFAULT posture still fails closed: the unimplemented seam throws (501 upstream)', async () => {
    await expect(
      new UnimplementedSessionJwtIssuer().issue({
        sessionId: SESSION_ID,
        walletCAddr: WALLET_C,
        issuedAt: NOW,
        expiresAt: NOW + 600,
      }),
    ).rejects.toThrow(/NOT IMPLEMENTED/);
  });
});
