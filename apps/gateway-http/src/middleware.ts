/**
 * Transport middleware, all of it in this one module:
 *
 *  1. REQUEST-ID — echo a valid inbound `X-Request-Id`, else mint `randomUUID()`. Set on EVERY
 *     response BEFORE any handler runs (unconditional), so an error response carries it too and a
 *     client can correlate a 500 to a log line.
 *  2. RAW-BODY CAPTURE — ONCE, into a Buffer, with a size cap (default `MAX_WEBHOOK_BODY_BYTES`,
 *     1 MiB, from the library). `Content-Length` pre-checked before reading; a mid-stream overflow
 *     destroys the request and answers 413. HMAC is linear in body length, so an unbounded body is
 *     an unauthenticated linear-cost DoS — the cap is the defence.
 *  3. JSON PARSE — only for opted-in routes (the webhook is deliberately NOT one of them: it must
 *     HMAC the raw bytes). A non-object body is refused 400. The raw body is NEVER echoed.
 *
 * The two response writers (`writeJson`, `writeError`) live here so handlers share one envelope
 */

import { randomUUID } from 'node:crypto';
import type { IncomingMessage, ServerResponse } from 'node:http';


import { HttpError, SubjectMismatchError, UnauthorizedError } from './errors.js';
import type { RouteContext } from './types.js';

/* -------------------------------------------------------------------------- */
/* Request id                                                                  */
/* -------------------------------------------------------------------------- */

/** An inbound id we will echo back. Conservative: bounded, ASCII alphanumeric + `-_.` only. */
const VALID_REQUEST_ID = /^[A-Za-z0-9._-]{1,128}$/;

/**
 * Resolve the request id: echo a valid inbound `X-Request-Id`, else a fresh `randomUUID()`. The
 * header is set UNCONDITIONALLY on the response here, before any handler runs, so an error path
 * cannot forget it.
 */
export function resolveRequestId(req: IncomingMessage, res: ServerResponse): string {
  const inbound = req.headers['x-request-id'];
  const id =
    typeof inbound === 'string' && VALID_REQUEST_ID.test(inbound) ? inbound : randomUUID();
  res.setHeader('x-request-id', id);
  return id;
}

/* -------------------------------------------------------------------------- */
/* Raw body capture                                                            */
/* -------------------------------------------------------------------------- */

/** The body cap, exported so middleware and the body-cap test share one constant. */
/** Largest request body the gateway reads: 1 MiB. */
export const BODY_CAP_BYTES = 1_048_576;

export class BodyTooLargeError extends Error {
  override readonly name = 'BodyTooLargeError';
  constructor() {
    super(`request body exceeds the ${BODY_CAP_BYTES}-byte cap`);
  }
}

/**
 * Capture the request body into a Buffer, ONCE. Refuses a body whose declared `Content-Length`
 * already exceeds the cap, and a body that grows past the cap mid-stream.
 *
 * On overflow we PAUSE the request stream and reject with {@link BodyTooLargeError} rather than
 * `req.destroy()`. Destroying the socket would tear down the very connection we need to deliver
 * the 413 on — the client (e.g. undici's fetch) would see a connection reset instead of the status
 * code. Pausing stops accepting further bytes (the same "no more data" the plan means by "destroy
 * the request") while leaving the response writable.
 */
export function captureBody(req: IncomingMessage, cap = BODY_CAP_BYTES): Promise<Buffer> {
  return new Promise<Buffer>((resolve, reject) => {
    const declared = req.headers['content-length'];
    if (declared !== undefined) {
      const n = Number(declared);
      if (Number.isFinite(n) && n > cap) {
        reject(new BodyTooLargeError());
        return;
      }
    }
    const chunks: Buffer[] = [];
    let total = 0;
    let settled = false;

    const fail = (err: Error): void => {
      if (settled) return;
      settled = true;
      req.removeListener('data', onData);
      req.removeListener('end', onEnd);
      req.removeListener('error', onError);
      reject(err);
    };

    const onData = (chunk: Buffer): void => {
      total += chunk.length;
      if (total > cap) {
        req.pause();
        fail(new BodyTooLargeError());
        return;
      }
      chunks.push(chunk);
    };
    const onEnd = (): void => {
      if (settled) return;
      settled = true;
      resolve(Buffer.concat(chunks));
    };
    const onError = (err: Error): void => {
      fail(err);
    };

    req.on('data', onData);
    req.on('end', onEnd);
    req.on('error', onError);
  });
}

/* -------------------------------------------------------------------------- */
/* JSON parse                                                                  */
/* -------------------------------------------------------------------------- */

/** Parse a raw body as a JSON OBJECT, or refuse. Never echoes the body in the message. */
export function parseJsonObject(raw: Buffer): unknown {
  if (raw.length === 0) {
    throw new HttpError({ status: 400, code: 'invalid_json', retriable: false },
      'expected a JSON object body');
  }
  let value: unknown;
  try {
    value = JSON.parse(raw.toString('utf8'));
  } catch {
    throw new HttpError({ status: 400, code: 'invalid_json', retriable: false },
      'request body is not valid JSON');
  }
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new HttpError({ status: 400, code: 'invalid_json', retriable: false },
      'request body must be a JSON object');
  }
  return value;
}

/** Read a required string field from a parsed object, or throw 400. */
export function requireString(body: Record<string, unknown>, key: string): string {
  const v = body[key];
  if (typeof v !== 'string' || v.length === 0) {
    throw new HttpError({ status: 400, code: 'missing_field', retriable: false },
      `missing or invalid "${key}"`);
  }
  return v;
}

/** Read an optional u32 field from a parsed object. `undefined` when absent. */
export function optionalU32(body: Record<string, unknown>, key: string): number | undefined {
  const v = body[key];
  if (v === undefined) return undefined;
  if (typeof v !== 'number' || !Number.isInteger(v) || v < 0 || v > 0xffff_ffff) {
    throw new HttpError({ status: 400, code: 'invalid_field', retriable: false },
      `"${key}" must be a non-negative u32 integer`);
  }
  return v;
}

/* -------------------------------------------------------------------------- */
/* Session-subject binding (the founding lesson, `auth: 'session'` surface)     */
/* -------------------------------------------------------------------------- */

/**
 * THE ENFORCING LINE every `auth: 'session'` handler must call — the session-surface twin of
 * sep12.ts's `resolveBoundAccount`. A verified session JWT authorizes NOTHING by possession: its
 * a subject — the attestation body's `subject`, the session record behind an issue body's
 * `sessionId` — MUST equal it or the answer is the loud 403 `subject_mismatch`, never a silent
 * proved live that both `auth:'session'` routes shipped with the comparison missing.
 *
 * Refuses 401 when there is no `session` auth context at all (a route table that lost its tag),
 * so the failure direction is always closed.
 *
 * Returns the authenticated subject; the mismatch check has already happened when it returns.
 */
export function assertSessionSubjectBinding(ctx: RouteContext, addressedSubject: string): string {
  const authenticated = ctx.auth?.kind === 'session' ? ctx.auth.subject : undefined;
  if (authenticated === undefined) throw new UnauthorizedError();
  if (authenticated !== addressedSubject) throw new SubjectMismatchError();
  return authenticated;
}

/* -------------------------------------------------------------------------- */
/* Response writers                                                            */
/* -------------------------------------------------------------------------- */

export function writeJson(res: ServerResponse, status: number, body: unknown): void {
  const payload = JSON.stringify(body);
  res.statusCode = status;
  res.setHeader('content-type', 'application/json');
  res.end(payload);
}

export function writeError(res: ServerResponse, err: HttpError, requestId: string): void {
  writeJson(res, err.status, {
    error: { code: err.code, message: err.message, requestId },
  });
}

/** A parsed body as a plain object bag, for handlers. */
export function asRecord(json: unknown): Record<string, unknown> {
  return json !== null && typeof json === 'object' && !Array.isArray(json)
    ? (json as Record<string, unknown>)
    : {};
}
