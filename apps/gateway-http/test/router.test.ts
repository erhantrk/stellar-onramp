import { describe, expect, it } from 'vitest';

import { Router, assertValidPathEncoding } from '../src/router.js';
import type { Route, RouteHandler } from '../src/types.js';

const ok: RouteHandler = async () => {};

function sampleRoutes(): Route[] {
  return [
    { method: 'GET', pathTemplate: '/v1/.well-known/issuer', jsonBody: false, handler: ok },
    { method: 'GET', pathTemplate: '/v1/schema/{version}', jsonBody: false, handler: ok },
    { method: 'GET', pathTemplate: '/v1/status-list/{issuer_id}', jsonBody: false, handler: ok },
    { method: 'POST', pathTemplate: '/v1/session', jsonBody: true, handler: ok },
    { method: 'POST', pathTemplate: '/v1/hooks/provider', jsonBody: false, handler: ok },
  ];
}

describe('Router', () => {
  it('matches a literal path with the right method', () => {
    const r = new Router(sampleRoutes());
    const m = r.match('GET', '/v1/.well-known/issuer');
    expect(m.kind).toBe('ok');
  });

  it('captures {param} values', () => {
    const r = new Router(sampleRoutes());
    const m = r.match('GET', '/v1/schema/1');
    expect(m.kind).toBe('ok');
    if (m.kind === 'ok') {
      expect(m.params['version']).toBe('1');
      expect(m.params['issuer_id']).toBeUndefined();
    }
  });

  it('captures the multi-char issuer_id param', () => {
    const r = new Router(sampleRoutes());
    const m = r.match('GET', '/v1/status-list/abcd1234');
    expect(m.kind).toBe('ok');
    if (m.kind === 'ok') expect(m.params['issuer_id']).toBe('abcd1234');
  });

  it('reports no-path for an unknown route', () => {
    const r = new Router(sampleRoutes());
    expect(r.match('GET', '/v1/nope').kind).toBe('no-path');
    expect(r.match('POST', '/v1/webhooks/onfido').kind).toBe('no-path');
  });

  it('reports method-not-allowed with the Allow list', () => {
    const r = new Router(sampleRoutes());
    const m = r.match('POST', '/v1/.well-known/issuer');
    expect(m.kind).toBe('method-not-allowed');
    if (m.kind === 'method-not-allowed') expect(m.allow).toContain('GET');
  });

  it('first match wins for a given method', () => {
    // If we add a later literal route that would also match, the first table entry must win.
    const r = new Router([
      ...sampleRoutes(),
      { method: 'GET', pathTemplate: '/v1/schema/latest', jsonBody: false, handler: ok },
    ]);
    const m = r.match('GET', '/v1/schema/latest');
    expect(m.kind).toBe('ok');
    if (m.kind === 'ok') expect(m.params['version']).toBe('latest');
  });

  it('one path under several methods: each method reaches its own handler', () => {
    // REGRESSION. The scan used to stop at the first PATH match and answer method-not-allowed
    // from there, so a second method on the same path was unreachable — it got 405 with an
    // Allow list that named the method it was called with. Every registered path happened to
    const put: RouteHandler = async () => {};
    const del: RouteHandler = async () => {};
    const r = new Router([
      { method: 'GET', pathTemplate: '/v1/customer', jsonBody: false, handler: ok },
      { method: 'PUT', pathTemplate: '/v1/customer', jsonBody: true, handler: put },
      { method: 'DELETE', pathTemplate: '/v1/customer/{account}', jsonBody: false, handler: del },
    ]);
    const g = r.match('GET', '/v1/customer');
    const p = r.match('PUT', '/v1/customer');
    expect(g.kind).toBe('ok');
    expect(p.kind).toBe('ok');
    if (g.kind === 'ok' && p.kind === 'ok') {
      expect(g.handler).toBe(ok);
      expect(g.jsonBody).toBe(false);
      expect(p.handler).toBe(put);
      expect(p.jsonBody).toBe(true);
    }
    const d = r.match('DELETE', '/v1/customer/GABC');
    expect(d.kind).toBe('ok');
    if (d.kind === 'ok') expect(d.params['account']).toBe('GABC');

    // A method on that path that is registered nowhere still 405s, with both real methods.
    const post = r.match('POST', '/v1/customer');
    expect(post.kind).toBe('method-not-allowed');
    if (post.kind === 'method-not-allowed') expect([...post.allow].sort()).toEqual(['GET', 'PUT']);
  });

  it('trailing slash is tolerated', () => {
    const r = new Router(sampleRoutes());
    expect(r.match('GET', '/v1/.well-known/issuer/').kind).toBe('ok');
  });

  it('rejects an unterminated { template at construction', () => {
    expect(
      () => new Router([{ method: 'GET', pathTemplate: '/v1/bad/{version', jsonBody: false, handler: ok }]),
    ).toThrow();
  });

  it('escapes literal regex metacharacters', () => {
    const r = new Router([{ method: 'GET', pathTemplate: '/a/b.c', jsonBody: false, handler: ok }]);
    expect(r.match('GET', '/a/bXc').kind).toBe('no-path');
    expect(r.match('GET', '/a/b.c').kind).toBe('ok');
  });

  it('has the expected route count', () => {
    const r = new Router(sampleRoutes());
    expect(r.size).toBe(5);
  });
});

describe('assertValidPathEncoding', () => {
  it('accepts a clean path', () => {
    expect(assertValidPathEncoding('/v1/schema/1')).toBe(true);
  });

  it('accepts a valid percent-encoded path', () => {
    expect(assertValidPathEncoding('/v1/status-list/abc%20def')).toBe(true);
  });

  it('rejects a malformed percent-escape', () => {
    expect(assertValidPathEncoding('/v1/%zz')).toBe(false);
    expect(assertValidPathEncoding('/v1/%2')).toBe(false);
  });
});
