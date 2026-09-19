/**
 * Stellar address SHAPES as ONE module, shared by the router's compile-time param constraint and
 * every handler that reads an account/wallet out of a path/query/body (so the two can never
 * drift):
 *
 *   * the G-ACCOUNT address (`G` + 55 base32 chars) — the same regex the repo already pins in
 *     `packages/identity/src/schema.ts` (`computeSubjectBinding`) and `packages/sdk/src/store.ts`,
 *     restated here because the transport cannot import those packages' internals and the SHAPE is
 *     what this app enforces, not the binding math;
 *   * the CONTRACT address (`C` + 55 base32) — what `wallet_c_addr` names everywhere the spec uses
 *     it (the passkey smart wallet, spec :439/:453) and therefore what a session JWT's `sub`
 *
 * WHY THE ROUTER CONSTRAINS ON IT: `DELETE /sep12/customer/callback` used to fall through the
 * PUT-only literal into the `{account}` template and dispatch with `account = "callback"` where
 * the spec-shaped answer is 405. Constraining `{account}` to the G-address shape at ROUTER
 * COMPILE TIME makes the literal and the template disjoint, so the fall-through is structurally
 * impossible rather than ordering-dependent. See server.ts's route-table comment for the full
 * history.
 *
 * NOTE ON ENCODING: a conforming G-address is pure `[A-Z2-7]` — characters that never need
 * percent-encoding in a path. Matching runs on the UNDECODED path (server.ts validates encoding,
 * then matches bytes), so an encoded-G (`%47…`) or an embedded `%2F` fails this shape and is
 * refused at the router — fail-closed by construction: nothing legitimate ever needs the encoded
 * form.
 */

import { HttpError } from './errors.js';

/** Regex SOURCE (unanchored) for one path segment holding a Stellar G-address. */
export const G_ADDRESS_SOURCE = 'G[A-Z2-7]{55}';

/**
 * Regex SOURCE (unanchored) for a Stellar contract (C) address — same base32 body as the
 * G-address, different version letter (module docblock).
 */
export const C_ADDRESS_SOURCE = 'C[A-Z2-7]{55}';

/**
 * The UNANCHORED pattern for `Route.paramPatterns` — the router adds its own anchors when it
 * compiles the constraint into the route regex and refuses embedded ones.
 */
export const G_ADDRESS_PARAM_PATTERN = new RegExp(G_ADDRESS_SOURCE);

/** The anchored shape of a Stellar G-address (56 chars: `G` + 55 base32), for value checks. */
export const G_ADDRESS_PATTERN = new RegExp(`^${G_ADDRESS_SOURCE}$`);

/** The anchored shape of a Stellar contract address (`C` + 55 base32), for value checks. */
export const C_ADDRESS_PATTERN = new RegExp(`^${C_ADDRESS_SOURCE}$`);

/**
 * Validate a string AS a G-address, throwing the transport's 400 envelope on anything else.
 * Handlers re-run this even when the router has already constrained the segment (defense in
 * depth: the router proves the PATH matched; this proves the VALUE is well-formed before it is
 * used as a store key).
 */
export function assertGAddress(value: unknown, what: string): string {
  if (typeof value !== 'string' || !G_ADDRESS_PATTERN.test(value)) {
    throw new HttpError(
      { status: 400, code: 'invalid_field', retriable: false },
      `"${what}" must be a Stellar G-address`,
    );
  }
  return value;
}

/**
 * Validate a string AS a contract (C) address, same envelope and rationale as {@link assertGAddress}.
 * accepted as any non-empty string while becoming the session JWT's §5.2-pinned `sub` — the one
 * body field whose downstream consumers (the session store key, the token subject, credential
 * subject binding) ALL depend on its C-shape. Fail closed on anything that is not one.
 */
export function assertCAddress(value: unknown, what: string): string {
  if (typeof value !== 'string' || !C_ADDRESS_PATTERN.test(value)) {
    throw new HttpError(
      { status: 400, code: 'invalid_field', retriable: false },
      `"${what}" must be a Stellar contract (C) address`,
    );
  }
  return value;
}
