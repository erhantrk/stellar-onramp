import { describe, expect, it } from 'vitest';

import { VALID_WALLET_C_ADDR, makeConfig, runHandler } from './fakes.js';
import { sessionHandler } from '../src/handlers/session.js';
import { InMemorySessionStore } from '../src/seams/session-store.js';
import type { ResolvedAppConfig } from '../src/types.js';

const storeOf = (config: ResolvedAppConfig): InMemorySessionStore =>
  config.sessionStore as InMemorySessionStore;

async function runSession(
  config: ResolvedAppConfig,
  json: unknown,
): Promise<{ status: number; body: unknown }> {
  const handler = sessionHandler(config);
  const { status, body } = await runHandler(handler, {
    request: {} as unknown as import('node:http').IncomingMessage,
    method: 'POST',
    path: '/v1/session',
    params: {},
    rawBody: Buffer.from(JSON.stringify(json)),
    json,
  });
  return { status, body };
}

describe('session handler', () => {
  it('creates + stores a session and returns its id (with fake auth seams)', async () => {
    const config = (await makeConfig()) as unknown as ResolvedAppConfig;
    const store = storeOf(config);
    const before = store.size;
    const { status, body } = await runSession(config, { wallet_c_addr: VALID_WALLET_C_ADDR, chain_id: 'testnet' });
    expect(status).toBe(201);
    // documented on the handler, not silent.
    const b = body as { session_id: string; session_token: string; expires_at: number };
    expect(b.session_id).toBeTruthy();
    // makeConfig wires the REAL issuer, so the token is a genuine ES256 compact JWS (frozen
    // protected header), not a stub string.
    expect(b.session_token).toMatch(/^eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9\./);
    expect(b.expires_at).toBe(1_700_000_000 + 900);
    expect(store.size).toBe(before + 1);
    expect(store.get(b.session_id)?.walletCAddr).toBe(VALID_WALLET_C_ADDR);
    expect(store.get(b.session_id)?.status).toBe('pending');
    // join back to this session or the webhook's approval path can never find it.
    const configAny = config as unknown as { kycApplicantCreator: { seen: { walletCAddr: string; sessionId: string }[] } };
    expect(configAny.kycApplicantCreator.seen.at(-1)).toEqual({
      walletCAddr: VALID_WALLET_C_ADDR,
      sessionId: b.session_id,
    });
  });

  it('records the session even when the auth seams 501 (fail closed)', async () => {
    const { UnimplementedKycApplicantCreator } = await import('../src/seams/kyc-applicant.js');
    const { UnimplementedSessionJwtIssuer } = await import('../src/seams/session-jwt.js');
    const stubbed = (await makeConfig({
      kycApplicantCreator: new UnimplementedKycApplicantCreator(),
      sessionJwtIssuer: new UnimplementedSessionJwtIssuer(),
    })) as unknown as ResolvedAppConfig;

    const stubbedStore = storeOf(stubbed);
    const before = stubbedStore.size;
    const { status } = await runSession(stubbed, { wallet_c_addr: VALID_WALLET_C_ADDR, chain_id: 'testnet' });
    expect(status).toBe(501);
    // The session write happened BEFORE the seam refused, so it is auditable.
    expect(stubbedStore.size).toBe(before + 1);
  });

  it('refuses a missing or malformed field with 400 (wallet_c_addr + chain_id)', async () => {
    const config = (await makeConfig()) as unknown as ResolvedAppConfig;
    expect((await runSession(config, {})).status).toBe(400);                       // nothing
    // this endpoint yet).
    expect((await runSession(config, { walletCAddr: VALID_WALLET_C_ADDR })).status).toBe(400);
    expect((await runSession(config, { wallet_c_addr: VALID_WALLET_C_ADDR })).status).toBe(400);      // no chain_id
    expect((await runSession(config, { wallet_c_addr: VALID_WALLET_C_ADDR, chain_id: '' })).status).toBe(400);
    expect((await runSession(config, { wallet_c_addr: VALID_WALLET_C_ADDR, chain_id: 7 })).status).toBe(400);
    // Control bytes are malformed even though the charset is otherwise wide.
    expect((await runSession(config, { wallet_c_addr: VALID_WALLET_C_ADDR, chain_id: 'te\u0000st' })).status).toBe(400);
    // A passphrase-shaped id passes the WIDE charset (spaces/semicolons are plausible values).
    const ok = await runSession(config, {
      wallet_c_addr: VALID_WALLET_C_ADDR,
      chain_id: 'Test SDF Network ; September 2015',
    });
    expect(ok.status).toBe(201);
  });

  it('refuses a NON-C-shaped wallet_c_addr with 400', async () => {
    const config = (await makeConfig()) as unknown as ResolvedAppConfig;
    // A G-account is a fine Stellar address but NOT a contract address; spec :439 pins
    // wallet_c_addr to the passkey smart wallet's C-address.
    expect((await runSession(config, { wallet_c_addr: 'GBWALLET', chain_id: 'testnet' })).status).toBe(400);
    expect((await runSession(config, { wallet_c_addr: `${VALID_WALLET_C_ADDR}X`, chain_id: 'testnet' })).status).toBe(400); // 57 chars
    expect((await runSession(config, { wallet_c_addr: VALID_WALLET_C_ADDR.slice(0, 55), chain_id: 'testnet' })).status).toBe(400); // 55 chars
    expect((await runSession(config, { wallet_c_addr: 'Czz-not-base32-at-all', chain_id: 'testnet' })).status).toBe(400);
    expect((await runSession(config, { wallet_c_addr: 42, chain_id: 'testnet' })).status).toBe(400);
    // And the C-shape itself still passes.
    expect((await runSession(config, { wallet_c_addr: VALID_WALLET_C_ADDR, chain_id: 'testnet' })).status).toBe(201);
  });
});
