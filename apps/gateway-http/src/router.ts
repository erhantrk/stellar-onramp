/**
 * A tiny path router: a data table compiled once to regexes, matched by linear scan. No framework.
 *
 * ~9 routes, so a linear scan over compiled regexes is the right shape — the cost is trivial and
 * the ordering is explicit: the first route matching BOTH method and path wins, which is how
 * `/v1/.well-known/issuer` and `/v1/schema/{version}` and `/v1/status-list/{issuer_id}` coexist
 * without ambiguity. See `match` for why "both" is load-bearing and not always "first path match".
 *
 * The three non-`ok` outcomes are first-class: no path -> 404, path with wrong method -> 405 +
 * an `Allow` header naming every method the path accepts, malformed percent-encoding -> 400.
 * Percent-encoding is validated BEFORE matching, so a `%zz` cannot be routed anywhere.
 *
 * PARAM PATTERNS (`Route.paramPatterns`): a `{param}` compiles to a bare `([^/]+)` unless the
 * route constrains it, in which case the pattern's SOURCE is compiled INTO the route regex — the
 * constraint applies at MATCH time, before any handler exists, which is what makes a constrained
 * template disjoint from any literal route sharing its prefix (the SEP-12 `callback` case). The
 * constructor refuses an unusable pattern (one that could match empty, cross a `/`, capture,
 * carry anchors, or name a param the template does not have) — a mis-declared constraint must be
 * a boot-time crash, never a silently unconstrained route.
 */

import type { Route, RouteAuth, RouteHandler, RouteParams } from './types.js';

/** Escape regex metacharacters in a literal path segment. */
function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Refuse a param pattern that cannot do its one job: constrain ONE path segment. Every check
 * here is a different way a plausible-looking pattern would quietly under-constrain:
 *
 *   * matching ''            — an empty segment would make `/sep12/customer/` match the template;
 *   * matching '/'           — the segment would swallow the slash and fuse two segments into
 *                              one match, resurrecting exactly the `%2F` confusion this app
 *                              refuses everywhere else;
 *   * capturing groups       — params are extracted POSITIONALLY from exec groups; a capture
 *                              inside a pattern shifts every later param's index. Non-capturing
 *                              constructs (`(?:`, lookaheads/lookbehinds) are fine;
 *   * `^` or `$` inside      — callers who feel they must anchor have usually written a pattern
 *                              that only works by accident inside ours; anchors are ours to add;
 *   * un-compilable source   — a backreference with no group, say, throws at probe time.
 */
function assertUsableParamPattern(pattern: RegExp, name: string, template: string): void {
  const src = pattern.source;
  let anchored: RegExp;
  try {
    anchored = new RegExp(`^(?:${src})$`);
  } catch (cause) {
    throw new Error(
      `router: param pattern for "{${name}}" in "${template}" does not compile as a segment ` +
        `constraint: ${String(cause)}`,
    );
  }
  if (anchored.test('')) {
    throw new Error(
      `router: param pattern for "{${name}}" in "${template}" matches the empty string; a ` +
        'segment constraint must require at least one character',
    );
  }
  if (anchored.test('/')) {
    throw new Error(
      `router: param pattern for "{${name}}" in "${template}" can match "/"; a segment ` +
        'constraint must stay within one path segment',
    );
  }
  // Capturing-group scan. `\(` is a literal paren; anything else opening with `(?:`, `(?=` or
  // `(?!` does not capture; `(?<…)` (named group or lookbehind) is refused outright — named
  // groups DO capture, and refusing lookbehinds too costs nothing.
  for (let i = 0; i < src.length; i += 1) {
    if (src[i] !== '(') continue;
    let escapes = 0;
    let j = i - 1;
    while (j >= 0 && src[j] === '\\') {
      escapes += 1;
      j -= 1;
    }
    if (escapes % 2 === 1) continue; // escaped literal '('
    const next = src.slice(i + 1, i + 2);
    if (next === '?' && ![':', '=', '!'].includes(src.slice(i + 2, i + 3))) {
      throw new Error(
        `router: param pattern for "{${name}}" in "${template}" contains a capturing or named ` +
          'group; params are extracted positionally, so only non-capturing constructs ' +
          '((?:…), (?=…), (?!…)) are allowed',
      );
    }
    if (next !== '?') {
      throw new Error(
        `router: param pattern for "{${name}}" in "${template}" contains a bare capturing ` +
          'group; wrap it non-capturing ((?:…)) so positional param extraction stays stable',
      );
    }
  }
  if (/[\^$]/.test(src)) {
    throw new Error(
      `router: param pattern for "{${name}}" in "${template}" carries ^ or $; the compiled ` +
        'route regex is already anchored and embedded anchors only ever work by accident',
    );
  }
}

interface CompiledRoute {
  readonly method: string;
  readonly jsonBody: boolean;
  /** Auth mode, defaulted to `'none'` at compile time (a route that forgets is public). */
  readonly auth: RouteAuth;
  readonly handler: RouteHandler;
  readonly regex: RegExp;
  readonly paramNames: readonly string[];
}

/** Compile one `{param}` template into a regex + its parameter name list. */
function compile(
  template: string,
  paramPatterns: Readonly<Record<string, RegExp>> | undefined,
): { regex: RegExp; paramNames: string[] } {
  const paramNames: string[] = [];
  const parts: string[] = [];
  let literal = '';
  let i = 0;
  while (i < template.length) {
    const c = template[i] as string;
    if (c === '{') {
      const close = template.indexOf('}', i);
      if (close === -1) {
        throw new Error(`router: unterminated { in path template "${template}"`);
      }
      const name = template.slice(i + 1, close);
      if (!/^[A-Za-z0-9_]+$/.test(name)) {
        throw new Error(`router: invalid param name "${name}" in "${template}"`);
      }
      paramNames.push(name);
      parts.push(escapeRegex(literal));
      literal = '';
      const pattern = paramPatterns?.[name];
      if (pattern === undefined) {
        parts.push('([^/]+)');
      } else {
        // Compile-time, not handler-time: the constraint lives IN the route regex, so a
        // non-matching value leaves the route unmatched entirely (405/404 fall out of ordinary
        // routing) rather than reaching a handler that has to remember to re-check.
        // Capturing wrapper `(...)`, not `(?:...)`: the value must still be captured for
        // positional extraction, and that is safe exactly because assertUsableParamPattern
        // refuses any CAPTURING construct inside the source — one constrained param contributes
        // exactly one group, so indices stay aligned with paramNames.
        assertUsableParamPattern(pattern, name, template);
        parts.push(`(${String(pattern.source)})`);
      }
      i = close + 1;
    } else {
      literal += c;
      i += 1;
    }
  }
  parts.push(escapeRegex(literal));
  // A declared pattern for a name the template never mentions is a typo wearing a constraint's
  // clothes — refuse at boot rather than constrain nothing.
  if (paramPatterns !== undefined) {
    for (const name of Object.keys(paramPatterns)) {
      if (!paramNames.includes(name)) {
        throw new Error(
          `router: paramPatterns names "${name}" but the template "${template}" has no such param`,
        );
      }
    }
  }
  return { regex: new RegExp(`^${parts.join('')}\\/?$`), paramNames };
}

export type MatchResult =
  | { readonly kind: 'ok'; readonly handler: RouteHandler; readonly jsonBody: boolean; readonly auth: RouteAuth; readonly params: RouteParams }
  | { readonly kind: 'no-path' }
  | { readonly kind: 'method-not-allowed'; readonly allow: readonly string[] };

export class Router {
  readonly #routes: readonly CompiledRoute[];

  constructor(routes: readonly Route[]) {
    // Built field-by-field (not by spreading `r`) so an OMITTED `auth` defaults to 'none' instead
    // of surviving as undefined through a spread.
    this.#routes = routes.map((r) => ({
      method: r.method,
      jsonBody: r.jsonBody,
      auth: r.auth ?? 'none',
      handler: r.handler,
      ...compile(r.pathTemplate, r.paramPatterns),
    }));
  }

  /** Number of compiled routes, for tests. */
  get size(): number {
    return this.#routes.length;
  }

  /** True iff a path (before method) matches any route — used to build the 405 Allow list. */
  #anyMethodForPath(path: string): readonly string[] {
    const methods: string[] = [];
    for (const r of this.#routes) {
      if (r.regex.test(path)) methods.push(r.method);
    }
    return methods;
  }

  /**
   * Match a method + path. First route matching BOTH wins; a path that exists only under other
   * methods reports 405 with the Allow list; a path under no route reports no-path.
   *
   * THE SCAN DOES NOT STOP AT THE FIRST PATH MATCH, and it used to. While every registered path
   * registered (`GET` + `PUT /sep12/customer`) it meant the first entry SHADOWED the rest —
   * `PUT /sep12/customer` answered 405 `Allow: GET, PUT`, a 405 that lists the very method being
   */
  match(method: string, path: string): MatchResult {
    let pathMatched = false;
    for (const r of this.#routes) {
      if (!r.regex.test(path)) continue;
      pathMatched = true;
      if (r.method !== method) continue;
      const m = r.regex.exec(path);
      const params: RouteParams = {};
      if (m !== null) {
        for (let k = 0; k < r.paramNames.length; k += 1) {
          const name = r.paramNames[k] as string;
          params[name] = m[k + 1];
        }
      }
      return { kind: 'ok', handler: r.handler, jsonBody: r.jsonBody, auth: r.auth, params };
    }
    if (pathMatched) return { kind: 'method-not-allowed', allow: this.#anyMethodForPath(path) };
    return { kind: 'no-path' };
  }
}

/**
 * Validate the percent-encoding of a request path. A malformed `%zz` makes `decodeURIComponent`
 * throw; we refuse the request 400 before it can be routed (a `%` in a path is only meaningful as
 * an escape, so a broken one is a malformed request, not a route).
 */
export function assertValidPathEncoding(path: string): boolean {
  try {
    decodeURIComponent(path);
    return true;
  } catch {
    return false;
  }
}
