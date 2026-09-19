/**
 * The HTTP server. `buildServer(AppConfig)` wires the fail-closed seams, compiles the route table
 * and returns a `node:http.Server`. The request pipeline is the transport's whole job:
 *
 *   1. request-id set UNCONDITIONALLY on every response before anything else;
 *   2. percent-encoding validated (400 on a broken `%zz`);
 *   3. raw body captured once with the size cap (413 on overflow);
 *   4. route matched (404 no path, 405 + Allow on method mismatch);
 *   4½. ROUTE AUTH enforced per the matched route's `auth` mode (401/403) — BEFORE body parse:
 *        an unauthenticated caller never spends the JSON parser and never gets attacker-
 *        controlled JSON handed toward a handler;
 *   5. JSON parsed only for opted-in routes (the webhook is never one);
 *
 * The webhook duplicate ACK (a `WebhookReplayError` duplicate mapped to 200) flows through the
 * same writer, so an idempotent ack is indistinguishable from success by status — by design.
 */

import { createServer } from 'node:http';
import type { Server } from 'node:http';

import { enforceRouteAuth } from './auth.js';
import { HttpError, toHttpError } from './errors.js';
import {
  BodyTooLargeError,
  asRecord,
  captureBody,
  parseJsonObject,
  resolveRequestId,
  writeError,
} from './middleware.js';
import { Router, assertValidPathEncoding } from './router.js';
import { InMemorySessionStore } from './seams/session-store.js';
import { UnimplementedSessionJwtIssuer } from './seams/session-jwt.js';
import { UnimplementedKycApplicantCreator } from './seams/kyc-applicant.js';
import { wellKnownHandler } from './handlers/well-known.js';
import { schemaHandler } from './handlers/schema.js';
import { statusListHandler } from './handlers/status-list.js';
import { healthzHandler, readyzHandler } from './handlers/health.js';
import { sessionHandler } from './handlers/session.js';
import { issueHandler } from './handlers/issue.js';
import type { AppConfig, ResolvedAppConfig, Route, RouteContext } from './types.js';

/** A server that has not yet `listen()`ed, plus the Router for tests that want to introspect it. */
export interface GatewayServer extends Server {
  /** The compiled router (tests introspect routes / counts). */
  readonly router: Router;
}

/** Inline 501 dispatch for the NOT-BUILT admin surface (seam only). */
export function buildServer(config: AppConfig): GatewayServer {
  // Resolve the optional fail-closed seams to their Unimplemented stubs.
  const resolved: ResolvedAppConfig = {
    ...config,
    sessionJwtIssuer: config.sessionJwtIssuer ?? new UnimplementedSessionJwtIssuer(),
    kycApplicantCreator: config.kycApplicantCreator ?? new UnimplementedKycApplicantCreator(),
  };

  const routes: Route[] = [
    // Public, no auth (`auth` omitted = 'none').
    { method: 'GET', pathTemplate: '/v1/.well-known/issuer', jsonBody: false, handler: wellKnownHandler(resolved) },
    { method: 'GET', pathTemplate: '/v1/schema/{version}', jsonBody: false, handler: schemaHandler(resolved) },
    { method: 'GET', pathTemplate: '/v1/status-list/{issuer_id}', jsonBody: false, handler: statusListHandler(resolved) },
    { method: 'GET', pathTemplate: '/healthz', jsonBody: false, handler: healthzHandler(resolved) },
    { method: 'GET', pathTemplate: '/readyz', jsonBody: false, handler: readyzHandler(resolved) },
    // Onboarding. Session CREATION is public — a caller cannot present a session JWT to obtain
    // one; the session's sensitive successors (issue) are the gated cells.
    { method: 'POST', pathTemplate: '/v1/session', jsonBody: true, handler: sessionHandler(resolved) },
    // session JWT"); the handler additionally demands an APPROVED session (409 until then).
    { method: 'POST', pathTemplate: '/v1/credentials/issue', jsonBody: true, auth: 'session', handler: issueHandler(resolved) },
  ];

  const router = new Router(routes);

  const server = createServer((req, res) => {
    void handle(req, res, router, resolved);
  }) as GatewayServer;
  (server as { router: Router }).router = router;

  return server;
}

async function handle(
  req: import('node:http').IncomingMessage,
  res: import('node:http').ServerResponse,
  router: Router,
  config: ResolvedAppConfig,
): Promise<void> {
  // 1. Request-id on EVERY response, unconditionally, before handlers run.
  const requestId = resolveRequestId(req, res);
  const method = (req.method ?? 'GET').toUpperCase();
  const path = (req.url?.split('?')[0] ?? '/').replace(/\/+$/, '') || '/';

  try {
    // 2. Percent-encoding must be well-formed before we route anything.
    if (!assertValidPathEncoding(path)) {
      writeError(
        res,
        new HttpError({ status: 400, code: 'bad_encoding', retriable: false }, 'malformed percent-encoding'),
        requestId,
      );
      return;
    }

    // 3. Capture the raw body once, with the size cap.
    let rawBody: Buffer;
    try {
      rawBody = await captureBody(req);
    } catch (err) {
      if (err instanceof BodyTooLargeError) {
        writeError(
          res,
          new HttpError({ status: 413, code: 'body_too_large', retriable: false }, 'request body too large'),
          requestId,
        );
      } else {
        writeError(res, toHttpError(err), requestId);
      }
      return;
    }

    // 4. Match.
    const match = router.match(method, path);
    if (match.kind === 'no-path') {
      writeError(res, new HttpError({ status: 404, code: 'not_found', retriable: false }, 'no such route'), requestId);
      return;
    }
    if (match.kind === 'method-not-allowed') {
      res.setHeader('allow', match.allow.join(', '));
      writeError(
        res,
        new HttpError({ status: 405, code: 'method_not_allowed', retriable: false }, 'method not allowed'),
        requestId,
      );
      return;
    }

    // 4½. ROUTE AUTH — before ANY parsing of caller-controlled content beyond the URL the router
    // already saw. The discriminator runs on the MATCH RESULT, so it sees exactly the path
    // `Router.match` saw (trailing slashes stripped at step 0, percent-encoding validated above);
    // there is no second URL parse here for a `%2F`-style differential to exploit.
    let auth: RouteContext['auth'];
    try {
      auth = await enforceRouteAuth(
        match.auth,
        req.headers as Record<string, string | readonly string[] | undefined>,
        {
          auth: config.auth,
          nowSeconds: config.now,
          // The 'admin' fall-through is safe only while the resolved seam refuses everything;
          // computed here where the resolution happened, one instanceof, never guessed.
        },
      );
    } catch (err) {
      writeError(res, toHttpError(err), requestId);
      return;
    }

    // 5. JSON only for opted-in routes.
    let json: unknown;
    if (match.jsonBody) {
      try {
        json = parseJsonObject(rawBody);
      } catch (err) {
        writeError(res, toHttpError(err), requestId);
        return;
      }
    }

    // 6. Dispatch.
    const ctx: RouteContext = {
      request: req,
      response: res,
      requestId,
      method,
      path,
      params: match.params,
      rawBody,
      json,
      ...(auth === undefined ? {} : { auth }),
    };
    try {
      await match.handler(ctx);
    } catch (err) {
      writeError(res, toHttpError(err), requestId);
    }
  } catch (err) {
    // Top-level safety net — a response is only written if one has not already started.
    if (!res.headersSent) writeError(res, toHttpError(err), requestId);
  }
}

// Re-exported so `asRecord` is reachable for anyone building custom handlers against this package.
export { asRecord };

export { InMemorySessionStore };
