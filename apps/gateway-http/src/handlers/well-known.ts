/**
 *
 * EVERY FIELD IS DERIVED, WITH NO OVERRIDE LEFT. This handler used to carry
 * `generators_root`/`generators[]` from config and 503 if a production config omitted them,
 * because `packages/identity` did not export them. It does now (`bbsGenerators()`), derived from
 * the ciphersuite's domain-separation tags and pinned byte-for-byte against the contract's own
 * `create_generators` on both sides (`packages/identity/test/generators.test.ts`,
 * `bbs_generators_match_the_typescript_export`), so there is nothing for an operator to configure
 * wrongly and nothing to fail closed on.
 *
 * It survived one commit as an "override for a v2-migration issuer serving a different L", and
 * that justification does not hold: `contracts/kyc-gate/src/bbs.rs` derives `count =
 * config; and this document would still publish `schema_version` and `ciphersuite` from this
 * build's frozen constants, making the overridden document self-inconsistent rather than a v2 one.
 * Meanwhile the override took an opaque (root, list) pair with no check that the root was
 * `sha256(concat(list))`, that the entries were 96-byte hex, or that there were L+1 of them —
 * `test/fakes.ts` really did carry `{generatorsRoot: '0x01', generators: ['0x02','0x03']}` and it
 * would have been served verbatim. Deriving leaves no argument to get wrong; accepting left one.
 *
 * The generators are published in their 96-byte UNCOMPRESSED form, the same encoding
 * `generators_root` hashes, so a reader with a hash function and no curve library can verify the
 * root straight off the document — and `generators_encoding` SAYS SO on the wire, because the two
 * plausible compressed readings hash to different 32-byte values and nothing about a bare digest
 */

import { writeJson } from '../middleware.js';
import type { AppConfig, RouteHandler } from '../types.js';

import {
  CIPHERSUITE,
  GENERATORS_ROOT_ENCODING,
  SCHEMA_VERSION,
  bbsGenerators,
  decompressG2,
  issuerIdFromPublicKey,
  toHex,
} from '@stellaronramp/identity';

export function wellKnownHandler(config: AppConfig): RouteHandler {
  return async (ctx) => {
    const derived = bbsGenerators();
    const pkCompressed = config.issuerPublicKey; // 96-byte compressed G2
    const pkUncompressed = decompressG2(pkCompressed); // 192-byte uncompressed G2
    writeJson(ctx.response, 200, {
      issuer_id: issuerIdFromPublicKey(pkCompressed),
      pk_g2_compressed: toHex(pkCompressed),
      pk_g2_uncompressed: toHex(pkUncompressed),
      ciphersuite: CIPHERSUITE,
      schema_version: SCHEMA_VERSION,
      registry_contract_id: config.kycRegistryContractId,
      gate_contract_id: config.kycGateContractId,
      network: config.network,
      network_passphrase: config.networkPassphrase,
      generators_root: derived.root,
      generators_encoding: GENERATORS_ROOT_ENCODING,
      generators: [...derived.uncompressed],
    });
  };
}
