import { describe, expect, it } from 'vitest';

import { VALID_WALLET_A, VALID_WALLET_B, makeConfig, runHandler } from './fakes.js';
import { issueHandler } from '../src/handlers/issue.js';
import type { AuthenticatedRequest, ResolvedAppConfig } from '../src/types.js';

/**
 * session's wallet, so every case here presents the credential the dispatcher would have set —
 * `auth` on the ctx is what a real request carries past the route gate.
 */
function asSession(subject: string): AuthenticatedRequest {
  return { kind: 'session', subject };
}

async function runIssue(
  config: ResolvedAppConfig,
  json: unknown,
  auth: AuthenticatedRequest = asSession(VALID_WALLET_A),
): Promise<{ status: number; body: unknown }> {
  const handler = issueHandler(config);
  const { status, body } = await runHandler(handler, {
    request: {} as unknown as import('node:http').IncomingMessage,
    method: 'POST',
    path: '/v1/credentials/issue',
    params: {},
    rawBody: Buffer.from(JSON.stringify(json)),
    json,
    auth,
  });
  return { status, body };
}

const NOW = 1_700_000_000;
const VALID_CLAIMS = {
  over18: true,
  over21: true,
  notSanctioned: true,
  notPep: true,
  jurisdictionOk: true,
  livenessOk: false,
};

describe('issue handler', () => {
  it('refuses a PENDING session with 409 (mutation #5)', async () => {
    const config = (await makeConfig()) as unknown as ResolvedAppConfig;
    const sessionId = await config.sessionStore.create(VALID_WALLET_A, NOW);
    const { status } = await runIssue(config, { sessionId, ...VALID_CLAIMS });
    expect(status).toBe(409);
  });

  it('refuses an UNKNOWN session with 409', async () => {
    const config = (await makeConfig()) as unknown as ResolvedAppConfig;
    const { status } = await runIssue(config, { sessionId: 'nope', ...VALID_CLAIMS });
    expect(status).toBe(409);
  });

  it('issues a credential for an APPROVED session (mutation #5)', async () => {
    const config = (await makeConfig()) as unknown as ResolvedAppConfig;
    const sessionId = await config.sessionStore.create(VALID_WALLET_A, NOW);
    config.sessionStore.setStatus(sessionId, 'approved');

    const { status, body } = await runIssue(config, { sessionId, ...VALID_CLAIMS });
    expect(status).toBe(201);
    const b = body as { claim_bitmap: number; revocation_index: number; subject_binding_salt: string };
    expect(b.claim_bitmap).toBeGreaterThan(0);
    expect(typeof b.revocation_index).toBe('number');
    expect(b.subject_binding_salt).toMatch(/^[0-9a-f]+$/);
  });

  it('refuses a missing sessionId with 400', async () => {
    const config = (await makeConfig()) as unknown as ResolvedAppConfig;
    const { status } = await runIssue(config, { ...VALID_CLAIMS });
    expect(status).toBe(400);
  });

  it('refuses a non-boolean claim with 400', async () => {
    const config = (await makeConfig()) as unknown as ResolvedAppConfig;
    const sessionId = await config.sessionStore.create(VALID_WALLET_A, NOW);
    config.sessionStore.setStatus(sessionId, 'approved');
    const { status } = await runIssue(config, { sessionId, ...VALID_CLAIMS, over18: 'yes' });
    expect(status).toBe(400);
  });

  it('binds the credential to the SESSION wallet, not the body', async () => {
    const config = (await makeConfig()) as unknown as ResolvedAppConfig;
    const sessionId = await config.sessionStore.create(VALID_WALLET_B, NOW);
    config.sessionStore.setStatus(sessionId, 'approved');
    // Authenticated AS B (the session's own wallet); a body `walletAddress` is still ignored.
    const { status } = await runIssue(
      config,
      { sessionId, walletAddress: VALID_WALLET_A, ...VALID_CLAIMS },
      asSession(VALID_WALLET_B),
    );
    expect(status).toBe(201);
    expect(config.sessionStore.get(sessionId)?.walletCAddr).toBe(VALID_WALLET_B);
  });

  it('refuses A-token against B-approved session with loud 403 subject_mismatch', async () => {
    // driving issuance against wallet B's approved session. Binding must answer BEFORE any
    // issuance spend, with its own machine code.
    const config = (await makeConfig()) as unknown as ResolvedAppConfig;
    const sessionIdB = await config.sessionStore.create(VALID_WALLET_B, NOW);
    config.sessionStore.setStatus(sessionIdB, 'approved');
    const { status, body } = await runIssue(
      config,
      { sessionId: sessionIdB, ...VALID_CLAIMS },
      asSession(VALID_WALLET_A),
    );
    expect(status).toBe(403);
    expect((body as { error: { code: string } }).error.code).toBe('subject_mismatch');

    // Control: B's own token against B's own approved session issues normally.
    const ok = await runIssue(config, { sessionId: sessionIdB, ...VALID_CLAIMS }, asSession(VALID_WALLET_B));
    expect(ok.status).toBe(201);
  });

  it('answers a foreign session id 403 regardless of its approval state (no state oracle)', async () => {
    const config = (await makeConfig()) as unknown as ResolvedAppConfig;
    const pendingForeign = await config.sessionStore.create(VALID_WALLET_B, NOW); // NOT approved
    const { status, body } = await runIssue(
      config,
      { sessionId: pendingForeign, ...VALID_CLAIMS },
      asSession(VALID_WALLET_A),
    );
    // Binding fires before the approval verdict: A learns nothing about B's session state.
    expect(status).toBe(403);
    expect((body as { error: { code: string } }).error.code).toBe('subject_mismatch');
  });
});
