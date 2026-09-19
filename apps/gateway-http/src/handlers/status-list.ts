/**
 *
 * The list is built and signed by the library's `publishStatusList`, from the configured revoked
 * set. The path's `{issuer_id}` must match OUR issuer id (a list served under another issuer's id
 * would be a poisoned mirror); anything else is 404. `validFrom` is the configured clock so a
 * test can pin it.
 */

import {
  G2_COMPRESSED_BYTES,
  issuerIdFromPublicKey,
  toHex,
} from '@stellaronramp/identity';
import { publishStatusList } from '@stellaronramp/gateway';

import { HttpError } from '../errors.js';
import { writeJson } from '../middleware.js';
import type { AppConfig, RouteHandler } from '../types.js';

export function statusListHandler(config: AppConfig): RouteHandler {
  return async (ctx) => {
    const issuer = ctx.params['issuer_id'];
    if (config.issuerPublicKey.length !== G2_COMPRESSED_BYTES) {
      throw new HttpError(
        { status: 503, code: 'issuer_config_incomplete', retriable: true },
        'issuer public key is not a 96-byte compressed G2 point',
      );
    }
    const ourIssuer = issuerIdFromPublicKey(config.issuerPublicKey);
    if (issuer !== ourIssuer) {
      throw new HttpError(
        { status: 404, code: 'status_list_not_found', retriable: false },
        'no status list for that issuer id',
      );
    }
    const document = await publishStatusList({
      url: config.statusListUrl,
      issuer: ourIssuer,
      verificationMethod: config.verificationMethod,
      statusPurpose: 'revocation',
      revoked: config.statusListStore.revokedIndexes(),
      validFromSeconds: config.now(),
      signingKey: config.statusListSigningKey,
    });
    writeJson(ctx.response, 200, document);
  };
}
