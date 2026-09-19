import { PassThrough } from 'node:stream';
import type { IncomingMessage } from 'node:http';
import { describe, expect, it } from 'vitest';

import {
  BODY_CAP_BYTES,
  BodyTooLargeError,
  captureBody,
  parseJsonObject,
  resolveRequestId,
} from '../src/middleware.js';

/** A fake IncomingMessage that emits the given chunks then ends, carrying headers. */
function fakeReq(headers: Record<string, string>, chunks: Buffer[]): IncomingMessage {
  const stream = new PassThrough();
  const req = stream as unknown as IncomingMessage;
  (req as { headers: Record<string, string> }).headers = { ...headers };
  for (const c of chunks) stream.write(c);
  stream.end();
  return req;
}

describe('resolveRequestId', () => {
  it('mints a request id when the header is absent', () => {
    const res = { setHeader: () => {} } as unknown as import('node:http').ServerResponse;
    const req = { headers: {} } as unknown as IncomingMessage;
    const id = resolveRequestId(req, res);
    expect(id).toMatch(/^[0-9a-f-]{36}$/);
  });

  it('echoes a valid inbound X-Request-Id', () => {
    const set = new Map<string, string>();
    const res = { setHeader: (k: string, v: string) => set.set(k, v) } as unknown as import('node:http').ServerResponse;
    const req = { headers: { 'x-request-id': 'trace-abc-123' } } as unknown as IncomingMessage;
    const id = resolveRequestId(req, res);
    expect(id).toBe('trace-abc-123');
    expect(set.get('x-request-id')).toBe('trace-abc-123');
  });

  it('mints a fresh id for an invalid inbound header (over-long / bad chars)', () => {
    const res = { setHeader: () => {} } as unknown as import('node:http').ServerResponse;
    const req = { headers: { 'x-request-id': 'x'.repeat(200) } } as unknown as IncomingMessage;
    expect(resolveRequestId(req, res).length).toBe(36);
    const req2 = { headers: { 'x-request-id': 'bad id with spaces' } } as unknown as IncomingMessage;
    expect(resolveRequestId(req2, res).length).toBe(36);
  });
});

describe('captureBody', () => {
  it('captures a small body once', async () => {
    const body = await captureBody(fakeReq({}, [Buffer.from('hello world')]));
    expect(body.toString('utf8')).toBe('hello world');
  });

  it('rejects a declared Content-Length over the cap without reading', async () => {
    const req = fakeReq({ 'content-length': String(BODY_CAP_BYTES + 1) }, [Buffer.from('x')]);
    await expect(captureBody(req)).rejects.toBeInstanceOf(BodyTooLargeError);
  });

  it('rejects a mid-stream overflow past the cap', async () => {
    // No content-length so the cap is enforced as bytes accumulate.
    const big = Buffer.alloc(BODY_CAP_BYTES + 10, 0x61);
    const req = fakeReq({}, [big]);
    await expect(captureBody(req)).rejects.toBeInstanceOf(BodyTooLargeError);
  });

  it('concatenates chunks across multiple data events', async () => {
    const req = fakeReq({}, [Buffer.from('a'), Buffer.from('b'), Buffer.from('c')]);
    const body = await captureBody(req);
    expect(body.toString('utf8')).toBe('abc');
  });
});

describe('parseJsonObject', () => {
  it('parses an object body', () => {
    expect(parseJsonObject(Buffer.from('{"a":1}'))).toEqual({ a: 1 });
  });

  it('refuses a non-object body (array, string, null)', () => {
    expect(() => parseJsonObject(Buffer.from('[1,2]'))).toThrow();
    expect(() => parseJsonObject(Buffer.from('"hi"'))).toThrow();
    expect(() => parseJsonObject(Buffer.from('null'))).toThrow();
  });

  it('refuses invalid JSON and an empty body', () => {
    expect(() => parseJsonObject(Buffer.from('{'))).toThrow();
    expect(() => parseJsonObject(Buffer.alloc(0))).toThrow();
  });
});
