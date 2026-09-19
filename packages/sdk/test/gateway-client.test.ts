/**
 * GatewayClient against a LOCAL node:http fixture server — typed error mapping by STATUS NUMBER
 * (never message strings), the real route shapes from apps/gateway-http/src/handlers/*, and the
 * credential path pinned both ways: GETs carry NO Authorization header ever, while issueCredential
 * presents the configured `sessionToken` and a MISSING one surfaces as GatewayUnauthorizedError.
 *
 * One case (`issueCredential crosses a REAL verifying gate`) binds a fixture that enforces the
 * bearer EXACTLY the way apps/gateway-http's dispatcher does — same `Bearer` extraction, same
 * library `verifyJws` under the strict claim policy, same loud subject binding — so the client's
 * presentation format is proven against the production verifier primitive, not a lookalike.
 * (The full dispatcher, over a real socket, is proven in gateway-http's own http-integration
 * suite; no cross-package dependency edge was added to prove it twice.)
 */

import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';

import { generateEs256KeyPair, signJws, verifyJws } from '@stellaronramp/gateway';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import {
  GatewayClient,
  GatewayForbiddenError,
  GatewayNotFoundError,
  GatewayNotImplementedError,
  GatewaySessionNotApprovedError,
  GatewayUnauthorizedError,
  GatewayUnavailableError,
  type IssuerDocument,
} from '../src/index.js';

let http: Server;
let baseUrl = '';
let lastHeaders: Record<string, string | string[] | undefined> = {};
/** Route table: "METHOD path" → [status, body]. */
let routes: Map<string, [number, unknown]>;
/** Last JSON body seen per "METHOD path". */
let seenBodies: Map<string, unknown>;

beforeEach(async () => {
  lastHeaders = {};
  routes = new Map();
  seenBodies = new Map();
  http = createServer((req, res) => {
    lastHeaders = req.headers;
    const url = (req.url ?? '').split('?')[0];
    const key = `${req.method} ${url}`;
    const entry = routes.get(key);
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      try {
        seenBodies.set(key, JSON.parse(Buffer.concat(chunks).toString('utf8') || 'null'));
      } catch {
        seenBodies.set(key, null);
      }
      res.setHeader('content-type', 'application/json');
      if (entry === undefined) {
        res.statusCode = 404;
        res.end(JSON.stringify({ error: { code: 'no_route', message: 'fixture has no such route' } }));
        return;
      }
      res.statusCode = entry[0];
      res.end(JSON.stringify(entry[1]));
    });
  });
  await new Promise<void>((resolve) => http.listen(0, '127.0.0.1', resolve));
  baseUrl = `http://127.0.0.1:${(http.address() as AddressInfo).port}`;
});

afterEach(async () => {
  await new Promise<void>((resolve) => http.close(() => resolve()));
});

const WELL_KNOWN: IssuerDocument = {
  issuer_id: 'a'.repeat(64),
  pk_g2_compressed: 'b'.repeat(192),
  pk_g2_uncompressed: 'c'.repeat(384),
  ciphersuite: 'BBS_BLS12381SHA256-SIGNATURE-2026-05-17',
  schema_version: '1',
  registry_contract_id: 'CAAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQC526',
  gate_contract_id: 'CABAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAFNSZ',
  network: 'testnet',
  network_passphrase: 'Test SDF Network ; September 2015',
  generators_root: 'd'.repeat(64),
  generators_encoding: 'sha256(g_1 ‖ … ‖ g_{L+1}), each g_i the 96-byte uncompressed be(X) ‖ be(Y)',
  generators: ['e'.repeat(192), 'f'.repeat(192)],
};

describe('GatewayClient', () => {
  it('wellKnownIssuer parses the real document shape', async () => {
    routes.set('GET /v1/.well-known/issuer', [200, WELL_KNOWN]);
    const client = new GatewayClient({ baseUrl });
    const doc = await client.wellKnownIssuer();
    expect(doc.schema_version).toBe('1');
    expect(doc.gate_contract_id).toMatch(/^C[A-Z2-7]{55}$/);
    expect(doc.generators.length).toBe(2);
  });

  it('schema(version) round-trips; a wrong version maps 404 → GatewayNotFoundError', async () => {
    routes.set('GET /v1/schema/1', [
      200,
      { schema_version: '1', attribute_count: 12, ciphersuite: 'cs', credential_header: 'hdr', claim_index: {} },
    ]);
    const client = new GatewayClient({ baseUrl });
    expect((await client.schema('1')).attribute_count).toBe(12);
    // No route for version 9 → fixture 404 with envelope code.
    await expect(client.schema('9')).rejects.toBeInstanceOf(GatewayNotFoundError);
  });

  it('statusList and healthz/readyz hit their real paths', async () => {
    routes.set('GET /v1/status-list/abc', [200, { id: 'list' }]);
    routes.set('GET /healthz', [200, { status: 'ok', service: 'gateway-http' }]);
    routes.set('GET /readyz', [200, { status: 'ready', network: 'testnet' }]);
    const client = new GatewayClient({ baseUrl });
    await expect(client.statusList('abc')).resolves.toEqual({ id: 'list' });
    await expect(client.healthz()).resolves.toEqual({ status: 'ok', service: 'gateway-http' });
    await expect(client.readyz()).resolves.toMatchObject({ status: 'ready' });
  });

  it('issueCredential POSTs sessionId + six booleans (+ optional expiresAt) to the real route', async () => {
    routes.set('POST /v1/credentials/issue', [
      201,
      {
        credential: {
          schemaVersion: '1',
          messages: ['m=1'],
          signature: 'aa',
          issuerPublicKey: 'bb',
          claims: {},
        },
        claim_bitmap: 5,
        revocation_index: 42,
        subject_binding_salt: 'ab'.repeat(32),
      },
    ]);

    const client = new GatewayClient({ baseUrl });
    const issued = await client.issueCredential({
      sessionId: 'sess_1',
      claims: {
        over18: true, over21: true, notSanctioned: true,
        notPep: false, jurisdictionOk: true, livenessOk: true,
      },
    });
    const body = seenBodies.get('POST /v1/credentials/issue') as Record<string, unknown>;
    expect(body['sessionId']).toBe('sess_1');
    expect(body['over18']).toBe(true);
    expect(body['notPep']).toBe(false);
    expect('expiresAt' in body).toBe(false); // omitted → server default (now + 24 h)
    expect('walletAddress' in body).toBe(false); // wallet comes from the SESSION
    expect(issued.claim_bitmap).toBe(5);
    expect(issued.subject_binding_salt).toMatch(/^(ab){32}$/);
  });

  it('409 on issue → GatewaySessionNotApprovedError (only the provider verdict approves a session)', async () => {
    routes.set('POST /v1/credentials/issue', [
      409,
      { error: { code: 'session_not_approved', message: 'prose never matched' } },
    ]);
    const client = new GatewayClient({ baseUrl });
    const err = await client
      .issueCredential({
        sessionId: 's',
        claims: { over18: true, over21: true, notSanctioned: true, notPep: true, jurisdictionOk: true, livenessOk: true },
      })
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(GatewaySessionNotApprovedError);
    expect((err as GatewaySessionNotApprovedError).code).toBe('session_not_approved');
    expect((err as GatewaySessionNotApprovedError).retriable).toBe(false);
    // And the prose was NOT matched — a different message with the same status classifies the same.
    expect((err as Error).message).not.toContain('prose never matched');
  });

  it.each([
    [501, GatewayNotImplementedError],
    [503, GatewayUnavailableError],
    [500, GatewayUnavailableError],
  ] as const)('status %i maps by TYPE to the right class', async (status, klass) => {
    routes.set('GET /healthz', [status, { error: { code: 'x' } }]);
    const client = new GatewayClient({ baseUrl });
    await expect(client.healthz()).rejects.toBeInstanceOf(klass);
  });

  it('a 501 carries retriable=false while other 5xx carry retriable=true', async () => {
    routes.set('GET /healthz', [501, {}]);
    const client = new GatewayClient({ baseUrl });
    const e1 = (await client.healthz().catch((e: unknown) => e)) as InstanceType<typeof GatewayNotImplementedError>;
    expect(e1).toBeInstanceOf(GatewayNotImplementedError);
    expect(e1.retriable).toBe(false);

    routes.set('GET /healthz', [503, {}]);
    const e2 = (await client.healthz().catch((e: unknown) => e)) as InstanceType<typeof GatewayUnavailableError>;
    expect(e2.retriable).toBe(true);
  });

  it('GETs SEND NO AUTHORIZATION HEADER (they are public routes; a session JWT there is 403 noise)', async () => {
    routes.set('GET /v1/.well-known/issuer', [200, WELL_KNOWN]);
    const client = new GatewayClient({ baseUrl, sessionToken: 'Bearer-material-unused-on-GETs' });
    await client.wellKnownIssuer();
    expect(lastHeaders['authorization']).toBeUndefined();
    expect(lastHeaders['cookie']).toBeUndefined();
  });

  it('issueCredential PRESENTS the configured sessionToken as Bearer on the gated route', async () => {
    routes.set('POST /v1/credentials/issue', [201, { credential: {}, claim_bitmap: 1, revocation_index: 2, subject_binding_salt: 'ab' }]);
    const client = new GatewayClient({ baseUrl, sessionToken: 'a.real.session-jwt' });
    await client.issueCredential({
      sessionId: 's',
      claims: { over18: true, over21: true, notSanctioned: true, notPep: true, jurisdictionOk: true, livenessOk: true },
    });
    expect(lastHeaders['authorization']).toBe('Bearer a.real.session-jwt');
    // And the supplier form is invoked PER CALL, so hosts can re-mint before the ≤15-min expiry.
    let mints = 0;
    const refreshing = new GatewayClient({
      baseUrl,
      sessionToken: () => {
        mints += 1;
        return Promise.resolve(`minted-${String(mints)}`);
      },
    });
    routes.set('POST /v1/credentials/issue', [201, { credential: {}, claim_bitmap: 1, revocation_index: 2, subject_binding_salt: 'ab' }]);
    await refreshing.issueCredential({
      sessionId: 's',
      claims: { over18: true, over21: true, notSanctioned: true, notPep: true, jurisdictionOk: true, livenessOk: true },
    });
    await refreshing.issueCredential({
      sessionId: 's',
      claims: { over18: true, over21: true, notSanctioned: true, notPep: true, jurisdictionOk: true, livenessOk: true },
    });
    expect(lastHeaders['authorization']).toBe('Bearer minted-2');
    expect(mints).toBe(2);
  });

  it('issueCredential WITHOUT a configured token maps the gateway 401 to GatewayUnauthorizedError', async () => {
    // fixed 401 and that MUST be a typed error, never prose matching.
    routes.set('POST /v1/credentials/issue', [
      401,
      { error: { code: 'unauthorized', message: 'authentication required' } },
    ]);
    const client = new GatewayClient({ baseUrl });
    const err = await client
      .issueCredential({
        sessionId: 's',
        claims: { over18: true, over21: true, notSanctioned: true, notPep: true, jurisdictionOk: true, livenessOk: true },
      })
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(GatewayUnauthorizedError);
    expect((err as GatewayUnauthorizedError).code).toBe('unauthorized');
    expect((err as GatewayUnauthorizedError).retriable).toBe(false);
    // Fixed client-side prose; the server's message text was never matched.
    expect((err as Error).message).toBe('authentication required by the gateway');
  });

  it('403 maps to GatewayForbiddenError (valid credential, wrong mode or wrong wallet)', async () => {
    routes.set('POST /v1/credentials/issue', [
      403,
      { error: { code: 'subject_mismatch', message: 'fixed prose' } },
    ]);
    const client = new GatewayClient({ baseUrl, sessionToken: 'someone-elses-token' });
    const err = await client
      .issueCredential({
        sessionId: 's',
        claims: { over18: true, over21: true, notSanctioned: true, notPep: true, jurisdictionOk: true, livenessOk: true },
      })
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(GatewayForbiddenError);
    expect((err as GatewayForbiddenError).code).toBe('subject_mismatch');
  });

  it('issueCredential crosses a REAL verifying gate (same verifyJws primitive + subject binding as the dispatcher)', async () => {
    const NOW = 1_700_000_000;
    const WALLET_C = 'CAJJ64SHO3R6L6ISWOD2NXACZXMQA6SAUXADCTSHDNLVZQ6Q3O5IVOVW';
    const ISSUER = 'https://gateway.test';
    const AUDIENCE = 'gateway-session';
    const { privateKey, publicKey } = generateEs256KeyPair();

    // A miniature of apps/gateway-http's gate: single Authorization header → strict verifyJws →
    // loud subject binding. Same library primitive, same refusal shapes.
    const sessions = new Map<string, string>([['sess-holder', WALLET_C]]);
    await new Promise<void>((resolve) => http.close(() => resolve()));
    http = createServer((req, res) => {
      lastHeaders = req.headers;
      const chunks: Buffer[] = [];
      req.on('data', (c: Buffer) => chunks.push(c));
      req.on('end', async () => {
        const body = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}') as Record<string, unknown>;
        const reply = (status: number, code: string, message: string): void => {
          res.statusCode = status;
          res.setHeader('content-type', 'application/json');
          res.end(JSON.stringify({ error: { code, message } }));
        };
        // Same two-step extraction as the dispatcher's extractBearer: prefix first, THEN the
        // no-whitespace discipline on the TOKEN (not the whole header value).
        const auth = lastHeaders['authorization'];
        const bearer = typeof auth === 'string' && !Array.isArray(auth) && auth.startsWith('Bearer ')
          ? auth.slice('Bearer '.length)
          : undefined;
        if (bearer === undefined || bearer.length === 0 || /\s/.test(bearer)) {
          return reply(401, 'unauthorized', 'authentication required');
        }
        let sub: string;
        try {
          const claims = await verifyJws(bearer, {
            publicKey,
            nowSeconds: NOW,
            issuer: ISSUER,
            audience: AUDIENCE,
          });
          sub = claims.sub;
        } catch {
          return reply(401, 'unauthorized', 'authentication required');
        }
        const wallet = sessions.get(String(body['sessionId']));
        if (wallet === undefined || wallet !== sub) {
          return reply(403, 'subject_mismatch', 'token subject does not match the addressed account');
        }
        res.statusCode = 201;
        res.setHeader('content-type', 'application/json');
        res.end(JSON.stringify({ credential: {}, claim_bitmap: 3, revocation_index: 7, subject_binding_salt: 'cd'.repeat(32) }));
      });
    });
    await new Promise<void>((resolve) => http.listen(0, '127.0.0.1', resolve));
    const realBase = `http://127.0.0.1:${(http.address() as AddressInfo).port}`;

    const mint = (): string =>
      signJws({
        privateKey,
        claims: { iss: ISSUER, sub: WALLET_C, aud: AUDIENCE, iat: NOW, nbf: NOW, exp: NOW + 600 },
      });

    // Holder's own token → through signature + claim + binding verification → 201 body parsed.
    const holder = new GatewayClient({ baseUrl: realBase, sessionToken: mint() });
    const issued = await holder.issueCredential({
      sessionId: 'sess-holder',
      claims: { over18: true, over21: true, notSanctioned: true, notPep: false, jurisdictionOk: true, livenessOk: true },
    });
    expect(issued.claim_bitmap).toBe(3);

    // A token for ANOTHER wallet clears signature+claims but fails BINDING → typed 403.
    const foreign = signJws({
      privateKey,
      claims: { iss: ISSUER, sub: 'GAOS3CYFTRFSBSVN4GORA3PSOIJICMMHDCRRQEOQDS42ASC4V52BXPE3', aud: AUDIENCE, iat: NOW, nbf: NOW, exp: NOW + 600 },
    });
    const attacker = new GatewayClient({ baseUrl: realBase, sessionToken: foreign });
    await expect(
      attacker.issueCredential({
        sessionId: 'sess-holder',
        claims: { over18: true, over21: true, notSanctioned: true, notPep: true, jurisdictionOk: true, livenessOk: true },
      }),
    ).rejects.toBeInstanceOf(GatewayForbiddenError);

    // No token at all → typed 401 (the stranded shape).
    const anonymous = new GatewayClient({ baseUrl: realBase });
    await expect(
      anonymous.issueCredential({
        sessionId: 'sess-holder',
        claims: { over18: true, over21: true, notSanctioned: true, notPep: true, jurisdictionOk: true, livenessOk: true },
      }),
    ).rejects.toBeInstanceOf(GatewayUnauthorizedError);
  });

  it('an unreachable base URL surfaces as GatewayUnavailableError via fetch failure? NO — transport throws raw', async () => {
    // Documented honestly: fetch-level failures are NOT mapped into the taxonomy here; only HTTP
    // responses are. Callers wrapping this client decide their own transport policy.
    const dead = new GatewayClient({ baseUrl: 'http://127.0.0.1:1', timeoutMs: 1500 });
    await expect(dead.healthz()).rejects.toThrow();
  });
});
