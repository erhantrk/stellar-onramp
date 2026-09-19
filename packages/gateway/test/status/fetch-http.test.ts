/**
 * `FetchStatusListHttp` — the ONLY `StatusListHttp` implementation that ever runs in production.
 *
 * `resolver.test.ts` injects `FakeStatusListHttp`; that file says so in its own header ("NO NETWORK.
 * Every test injects `FakeStatusListHttp`. `FetchStatusListHttp` is never constructed."). That is the
 * right call for the resolver's logic, but it left the real adapter with ZERO coverage, and the real
 * adapter is where four controls actually live:
 *
 *   1. the `AbortController` timeout — proven absent by mutation: replacing
 *      `setTimeout(() => controller.abort(), ...)` with `setTimeout(() => {}, ...)` left the whole
 *      suite GREEN. `resolver.test.ts` asserts only that an injected `AbortError` is CLASSIFIED as
 *      `timeout`; classification is not enforcement, and a hung origin hangs the verification.
 *   2. `redirect: 'manual'` — the source comment claims it is "asserted by a test that hands the
 *      resolver a 302". That test hands a 302 to a FAKE. An implementation that let `fetch` follow
 *      redirects internally would silently disable BOTH the per-hop HTTPS downgrade check and the
 *      hop counter, and no test would have noticed.
 *   3. the `content-length` pre-check, which refuses before reading a byte.
 *   4. the STREAMING size cap, which is the difference between aborting a 4 GB response and
 *      allocating 4 GB and then measuring it.
 *
 * STILL NO NETWORK. `globalThis.fetch` is stubbed per-test with `vi.stubGlobal`; nothing here opens a
 * socket, so `npx vitest run` never reaches the wire.
 */

import { afterEach, describe, expect, it, vi } from 'vitest';

import { FetchStatusListHttp, StatusListResolutionError } from '../../src/status/resolver.js';

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

const OPTIONS = { timeoutMs: 50, maxBytes: 1024 };

/** A `Response` whose body is delivered as the given chunks, so the streaming cap is exercised. */
function streamingResponse(
  chunks: readonly Uint8Array[],
  init: { status?: number; headers?: Record<string, string> } = {},
): Response {
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      for (const c of chunks) controller.enqueue(c);
      controller.close();
    },
  });
  return new Response(stream, {
    status: init.status ?? 200,
    headers: init.headers ?? {},
  });
}

describe('FetchStatusListHttp: the AbortController timeout is ENFORCED, not merely classified', () => {
  it('aborts a hung origin, so a verification cannot hang forever', async () => {
    // A fetch that resolves only when the signal fires — i.e. a server that accepted the connection
    // and then said nothing, which is the realistic hang and the one a connect timeout misses.
    let signalSeen: AbortSignal | undefined;
    vi.stubGlobal('fetch', (_url: string, init: RequestInit) => {
      signalSeen = init.signal ?? undefined;
      return new Promise<Response>((_resolve, reject) => {
        init.signal?.addEventListener('abort', () => {
          reject(Object.assign(new Error('The operation was aborted.'), { name: 'AbortError' }));
        });
      });
    });

    const started = Date.now();
    await expect(new FetchStatusListHttp().get('https://list.example/l', OPTIONS)).rejects.toThrow(
      /abort/i,
    );
    // The bound is what matters, not the exact millisecond: without the abort this never settles at
    // all, so any finite completion is the control working. Generous upper bound for a loaded box.
    expect(Date.now() - started).toBeLessThan(15_000);
    expect(signalSeen).toBeInstanceOf(AbortSignal);
    expect(signalSeen?.aborted).toBe(true);
  });

  it('passes a signal that is NOT already aborted on the happy path, and clears its timer', async () => {
    let signalSeen: AbortSignal | undefined;
    vi.stubGlobal('fetch', (_url: string, init: RequestInit) => {
      signalSeen = init.signal ?? undefined;
      return Promise.resolve(streamingResponse([new Uint8Array([123, 125])]));
    });

    const clearSpy = vi.spyOn(globalThis, 'clearTimeout');
    const res = await new FetchStatusListHttp().get('https://list.example/l', OPTIONS);
    expect(res.status).toBe(200);
    expect(signalSeen?.aborted).toBe(false);
    // A leaked timer keeps the event loop alive and turns a passing suite into one that never
    // exits — the source comment says the clear is in a `finally`; this is what proves it.
    expect(clearSpy).toHaveBeenCalled();
    clearSpy.mockRestore();
  });

  it('clears the timer even when the fetch REJECTS, not only on the happy path', async () => {
    vi.stubGlobal('fetch', () => Promise.reject(new Error('ECONNREFUSED')));
    const clearSpy = vi.spyOn(globalThis, 'clearTimeout');
    await expect(
      new FetchStatusListHttp().get('https://list.example/l', OPTIONS),
    ).rejects.toThrow(/ECONNREFUSED/);
    expect(clearSpy).toHaveBeenCalled();
    clearSpy.mockRestore();
  });
});

describe('FetchStatusListHttp: redirect discipline is set on the REAL fetch call', () => {
  it("requests redirect:'manual' so the resolver sees every hop", async () => {
    let init: RequestInit | undefined;
    vi.stubGlobal('fetch', (_url: string, i: RequestInit) => {
      init = i;
      return Promise.resolve(
        streamingResponse([], { status: 302, headers: { location: 'https://b.example/l' } }),
      );
    });

    const res = await new FetchStatusListHttp().get('https://a.example/l', OPTIONS);

    // If this were 'follow' (the fetch default), the adapter would hand back the FINAL response and
    // the resolver would never see the hop — silently disabling the HTTPS-downgrade check on every
    // redirect and the redirect cap at the same time. Both are the MITM-un-revokes-anybody hole.
    expect(init?.redirect).toBe('manual');
    expect(res.status).toBe(302);
    expect(res.headers['location']).toBe('https://b.example/l');
  });

  it('lowercases response header names, so the resolver can read `location` case-insensitively', async () => {
    vi.stubGlobal('fetch', () =>
      Promise.resolve(
        streamingResponse([], { status: 301, headers: { LoCaTiOn: 'https://b.example/l' } }),
      ),
    );
    const res = await new FetchStatusListHttp().get('https://a.example/l', OPTIONS);
    expect(res.headers['location']).toBe('https://b.example/l');
  });

  it('issues a GET and asks for JSON', async () => {
    let init: RequestInit | undefined;
    vi.stubGlobal('fetch', (_url: string, i: RequestInit) => {
      init = i;
      return Promise.resolve(streamingResponse([new Uint8Array([123, 125])]));
    });
    await new FetchStatusListHttp().get('https://a.example/l', OPTIONS);
    expect(init?.method).toBe('GET');
    expect((init?.headers as Record<string, string>)['accept']).toBe('application/json');
  });
});

describe('FetchStatusListHttp: the size cap is enforced in the REAL adapter', () => {
  it('refuses on content-length BEFORE reading a single byte of the body', async () => {
    let bodyRead = false;
    const stream = new ReadableStream<Uint8Array>(
      {
        pull(controller) {
          bodyRead = true;
          controller.enqueue(new Uint8Array(10));
          controller.close();
        },
      },
      // highWaterMark 0 on purpose. The DEFAULT strategy prefetches one chunk the moment the stream
      // is constructed, which would set `bodyRead` before the adapter ever looked at the body and
      // make this test fail against correct code. (It did, on the first run — the test was wrong,
      // not the adapter.) With a 0 mark, `pull` fires only when a read is actually pending, so
      // `bodyRead` means what its name says.
      new CountQueuingStrategy({ highWaterMark: 0 }),
    );
    vi.stubGlobal('fetch', () =>
      Promise.resolve(
        new Response(stream, { status: 200, headers: { 'content-length': '999999' } }),
      ),
    );

    const err = await new FetchStatusListHttp()
      .get('https://a.example/l', { timeoutMs: 1000, maxBytes: 64 })
      .then(
        () => undefined,
        (e: unknown) => e,
      );
    expect(err).toBeInstanceOf(StatusListResolutionError);
    expect((err as StatusListResolutionError).reason).toBe('response-too-large');
    expect(bodyRead).toBe(false);
  });

  it('STREAMS and aborts mid-body when content-length LIES about the size', async () => {
    // content-length is a hint from the server, not a bound. A server that under-declares gets past
    // the pre-check, so the streaming cap is the control that actually holds — this is the case that
    // distinguishes the two, and the reason both exist.
    const chunks = [new Uint8Array(40), new Uint8Array(40), new Uint8Array(40)];
    let chunksDelivered = 0;
    const stream = new ReadableStream<Uint8Array>(
      {
        pull(controller) {
          if (chunksDelivered === chunks.length) {
            controller.close();
            return;
          }
          controller.enqueue(chunks[chunksDelivered] as Uint8Array);
          chunksDelivered += 1;
        },
      },
      // See above: the default strategy prefetches, which would deliver every chunk regardless of
      // whether the adapter stopped reading, and this test's whole point is that it stopped.
      new CountQueuingStrategy({ highWaterMark: 0 }),
    );
    vi.stubGlobal('fetch', () =>
      Promise.resolve(new Response(stream, { status: 200, headers: { 'content-length': '10' } })),
    );

    const err = await new FetchStatusListHttp()
      .get('https://a.example/l', { timeoutMs: 1000, maxBytes: 64 })
      .then(
        () => undefined,
        (e: unknown) => e,
      );
    expect(err).toBeInstanceOf(StatusListResolutionError);
    expect((err as StatusListResolutionError).reason).toBe('response-too-large');
    expect((err as Error).message).toContain('aborted rather');
    // The read stopped at the cap instead of buffering everything and then measuring: chunk 3 was
    // never pulled. That is the whole difference from `await response.arrayBuffer()`.
    expect(chunksDelivered).toBeLessThan(chunks.length);
  });

  it('accepts a body exactly AT the cap (the bound is inclusive, not off by one)', async () => {
    vi.stubGlobal('fetch', () =>
      Promise.resolve(streamingResponse([new Uint8Array(64).fill(32)])),
    );
    const res = await new FetchStatusListHttp().get('https://a.example/l', {
      timeoutMs: 1000,
      maxBytes: 64,
    });
    expect(res.body.length).toBe(64);
  });

  it('refuses at cap+1', async () => {
    vi.stubGlobal('fetch', () =>
      Promise.resolve(streamingResponse([new Uint8Array(65).fill(32)])),
    );
    await expect(
      new FetchStatusListHttp().get('https://a.example/l', { timeoutMs: 1000, maxBytes: 64 }),
    ).rejects.toMatchObject({ reason: 'response-too-large' });
  });

  it('reassembles multi-chunk bodies in ORDER, so a split JSON document still parses', async () => {
    const text = '{"hello":"world","n":1234567890}';
    const bytes = Buffer.from(text, 'utf8');
    const chunks: Uint8Array[] = [];
    for (let i = 0; i < bytes.length; i += 5) chunks.push(bytes.subarray(i, i + 5));
    expect(chunks.length).toBeGreaterThan(3);
    vi.stubGlobal('fetch', () => Promise.resolve(streamingResponse(chunks)));

    const res = await new FetchStatusListHttp().get('https://a.example/l', OPTIONS);
    expect(Buffer.from(res.body).toString('utf8')).toBe(text);
  });

  it('tolerates a null body (a 304/204 has none) rather than throwing a TypeError', async () => {
    vi.stubGlobal('fetch', () => Promise.resolve(new Response(null, { status: 204 })));
    const res = await new FetchStatusListHttp().get('https://a.example/l', OPTIONS);
    expect(res.status).toBe(204);
    expect(res.body.length).toBe(0);
  });

  it('ignores a non-numeric content-length instead of treating NaN as over the cap', async () => {
    vi.stubGlobal('fetch', () =>
      Promise.resolve(
        streamingResponse([new Uint8Array([123, 125])], {
          headers: { 'content-length': 'not-a-number' },
        }),
      ),
    );
    const res = await new FetchStatusListHttp().get('https://a.example/l', OPTIONS);
    expect(res.status).toBe(200);
    expect(res.body.length).toBe(2);
  });
});

describe('FetchStatusListHttp: it is a StatusListHttp and nothing more', () => {
  it('exposes exactly one method, so the injectable seam stays five lines to fake', () => {
    const own = Object.getOwnPropertyNames(FetchStatusListHttp.prototype).filter(
      (n) => n !== 'constructor',
    );
    expect(own).toEqual(['get']);
  });

  it('does not read process.env, so it cannot be reconfigured by ambient state', () => {
    const src = FetchStatusListHttp.prototype.get.toString();
    expect(src).not.toContain('process.env');
  });
});
