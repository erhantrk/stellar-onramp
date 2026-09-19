/**
 * Route authentication. The only credential the gateway accepts is the session JWT it issued at
 * `POST /v1/session`: an ES256 bearer token whose subject is the wallet contract address. A route
 * marked `auth: 'session'` gets a verified `{ kind: 'session', subject }`; anything else is 401.
 */

import { verifyJws } from '@stellaronramp/gateway';

import { UnauthorizedError } from './errors.js';
import type { AuthenticatedRequest, GatewayAuthConfig, RouteAuth } from './types.js';

const AUTHORIZATION_HEADER = 'authorization';
/** Longer than any real token; a bound so a hostile header is refused before it is parsed. */
const MAX_CREDENTIAL_CHARS = 8192;

export interface AuthenticatorDeps {
  readonly auth?: GatewayAuthConfig | undefined;
  readonly nowSeconds: () => number;
}

function readSingleHeaderValue(
  headers: Record<string, string | readonly string[] | undefined>,
  name: string,
): string | undefined {
  const value = headers[name];
  if (value === undefined) return undefined;
  if (Array.isArray(value)) return value.length === 1 ? (value[0] as string) : undefined;
  return value as string;
}

function extractBearer(value: string | undefined): string {
  if (value === undefined) throw new UnauthorizedError();
  if (value.length > MAX_CREDENTIAL_CHARS) throw new UnauthorizedError();
  if (!value.startsWith('Bearer ')) throw new UnauthorizedError();
  const token = value.slice('Bearer '.length);
  if (token.length === 0 || token.includes(' ') || token.includes('\t')) {
    throw new UnauthorizedError();
  }
  return token;
}

async function verifySessionBearer(
  deps: AuthenticatorDeps,
  headers: Record<string, string | readonly string[] | undefined>,
): Promise<AuthenticatedRequest> {
  if (deps.auth === undefined) throw new UnauthorizedError();
  const token = extractBearer(readSingleHeaderValue(headers, AUTHORIZATION_HEADER));
  try {
    const claims = await verifyJws(token, {
      publicKey: deps.auth.sessionJwt.publicKey,
      nowSeconds: deps.nowSeconds(),
      issuer: deps.auth.sessionJwt.issuer,
      audience: deps.auth.sessionJwt.audience,
    });
    return { kind: 'session', subject: claims.sub };
  } catch {
    throw new UnauthorizedError();
  }
}

export async function enforceRouteAuth(
  mode: RouteAuth,
  headers: Record<string, string | readonly string[] | undefined>,
  deps: AuthenticatorDeps,
): Promise<AuthenticatedRequest | undefined> {
  if (mode === 'none') return undefined;
  return verifySessionBearer(deps, headers);
}
