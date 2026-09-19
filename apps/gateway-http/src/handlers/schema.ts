/**
 *
 * Projects the frozen v1 schema (packages/identity CLAIM_INDEX) as a public, machine-readable
 * document. A version other than the live `SCHEMA_VERSION` is 404 — there is no other schema to
 * serve, and inventing one would let a holder pin a version that does not exist.
 */

import {
  CIPHERSUITE,
  CLAIM_INDEX,
  CREDENTIAL_HEADER,
  SCHEMA_ATTRIBUTE_COUNT,
  SCHEMA_VERSION,
} from '@stellaronramp/identity';

import { HttpError } from '../errors.js';
import { writeJson } from '../middleware.js';
import type { AppConfig, RouteHandler } from '../types.js';

export function schemaHandler(_config: AppConfig): RouteHandler {
  return async (ctx) => {
    const version = ctx.params['version'];
    if (version !== SCHEMA_VERSION) {
      throw new HttpError(
        { status: 404, code: 'schema_not_found', retriable: false },
        `no schema version "${String(version)}"; the only version is ${SCHEMA_VERSION}`,
      );
    }
    writeJson(ctx.response, 200, {
      schema_version: SCHEMA_VERSION,
      attribute_count: SCHEMA_ATTRIBUTE_COUNT,
      ciphersuite: CIPHERSUITE,
      credential_header: CREDENTIAL_HEADER,
      claim_index: { ...CLAIM_INDEX },
    });
  };
}
