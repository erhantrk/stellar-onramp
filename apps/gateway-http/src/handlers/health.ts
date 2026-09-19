/**
 * Liveness and readiness. `GET /healthz` answers the instant the process is up; `GET /readyz`
 * answers only when the server is constructed with a fully-wired config (which is the only state
 */

import type { AppConfig, RouteHandler } from '../types.js';
import { writeJson } from '../middleware.js';

export function healthzHandler(_config: AppConfig): RouteHandler {
  return async (ctx) => {
    writeJson(ctx.response, 200, { status: 'ok', service: 'gateway-http' });
  };
}

export function readyzHandler(_config: AppConfig): RouteHandler {
  return async (ctx) => {
    writeJson(ctx.response, 200, { status: 'ready', network: _config.network });
  };
}
