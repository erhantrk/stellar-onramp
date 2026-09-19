/**
 * `loadSdkConfig(network, opts)`: read `deployments.json` (repo root) into the passive config
 * every SDK factory takes. Mirrors `apps/gateway-http/src/config.ts` — one function, one file,
 * the ONLY place this package reads the filesystem or an environment name — and deliberately
 * does NOT construct any network seam: the `rpc.Server`, the relayer client and the WebAuthn
 * implementation are injected by whoever owns the wiring (see `wallet/` and `attest/submit.ts`),
 * and tests never construct them.
 *
 * WHERE IT DIFFERS FROM THE TRANSPORT'S LOADER, and why it must: `apps/gateway-http` returns
 * empty contract ids for a network with nothing deployed and leaves failing closed to the caller.
 * An SDK consumer is the least-equipped caller to notice — a holder's browser app ships whatever
 * config object it was handed and only finds out on-chain. So THIS loader fails closed itself:
 * a missing file, an unknown network, an empty or malformed contract id, or a non-https RPC url
 * all throw here, before any caller can build a factory around them. `mainnet.contracts` is
 * empty today (no deploy — see deployments.json), so `loadSdkConfig('mainnet')` throws by
 * construction rather than handing out ids that would route a holder's credential to nothing.
 *
 * The rpcUrl comes from deployments.json `networkConfig.rpcUrl`, NOT from `process.env`: scripts
 * `process.env` inside a browser bundle is a crash. Callers who need an override pass a different
 * config object; that keeps "where did these values come from" answerable in one line.
 */

import { readFileSync } from 'node:fs';

export class SdkConfigError extends Error {
  override readonly name = 'SdkConfigError';
}

/** A Stellar contract id: `C` followed by 55 base32 characters. Checked by shape here; the
 *  checksum is validated by `Address.fromString` at first use on chain. */
const CONTRACT_ID_RE = /^C[A-Z2-7]{55}$/;

/** The passive values every SDK factory needs. Frozen by convention (callers hand it on). */
export interface SdkConfig {
  readonly network: 'testnet' | 'mainnet';
  readonly networkPassphrase: string;
  /** Soroban RPC endpoint, from deployments.json `networkConfig.rpcUrl`. */
  readonly rpcUrl: string;
  readonly kycGateContractId: string;
  readonly kycRegistryContractId: string;
}

interface DeploymentsFile {
  /** Mirrors apps/gateway-http/src/config.ts::DeploymentsFile — the values live PER NETWORK. */
  readonly testnet?: NetworkBlock;
  readonly mainnet?: NetworkBlock;
}

interface NetworkBlock {
  readonly networkPassphrase?: string;
  readonly networkConfig?: { readonly rpcUrl?: string };
  readonly contracts?: {
    readonly 'kyc-gate'?: { readonly id?: string };
    readonly 'kyc-registry'?: { readonly id?: string };
  };
}

/**
 * Resolve the deployments.json path. The file lives at the repo root; from this module (src or
 * dist, both THREE directories below root) `../../../deployments.json` lands on it regardless of
 * whether it is run by tsx from src or node from dist.
 */
function defaultDeploymentsPath(): string {
  return new URL('../../../deployments.json', import.meta.url).pathname;
}

export interface LoadSdkConfigOptions {
  /**
   * Override where deployments.json is read from. Tests use this to point at a fixture file so
   * the suite never depends on the repo-root deployment state; production never passes it.
   */
  readonly deploymentsPath?: string;
  /**
   * Allow a plain-`http://` RPC url. OFF by default and that is deliberate: an http endpoint
   * carries the wallet's RPC traffic in the clear, and a `mainnet` misconfiguration pointing at
   * `http://localhost:8000` should be loud here rather than silent on the wire. The same rule
   * exists in `packages/gateway/src/chain/epoch.ts` (`SorobanGateSimulator` refuses insecure
   * endpoints unless explicitly allowed); found there by writing a test against a dead endpoint.
   */
  readonly allowInsecureRpc?: boolean;
}

export function loadSdkConfig(
  env: string,
  opts: LoadSdkConfigOptions = {},
): SdkConfig {
  // `env === 'mainnet' ? 'mainnet' : 'testnet'` coerced a typo like 'mainet' onto testnet while
  // this file's own header promised unknown names throw. A typoed network must never silently
  // route a holder onto a different one.
  if (env !== 'mainnet' && env !== 'testnet') {
    throw new SdkConfigError(
      `unknown network "${env}" — expected 'mainnet' or 'testnet'`,
    );
  }
  const network: 'mainnet' | 'testnet' = env;
  const path = opts.deploymentsPath ?? defaultDeploymentsPath();
  let raw: string;
  try {
    raw = readFileSync(path, 'utf8');
  } catch (cause) {
    throw new SdkConfigError(`could not read deployments.json at ${path}: ${String(cause)}`);
  }
  let parsed: DeploymentsFile;
  try {
    parsed = JSON.parse(raw) as DeploymentsFile;
  } catch (cause) {
    throw new SdkConfigError(`deployments.json at ${path} is not valid JSON: ${String(cause)}`);
  }

  const block: NetworkBlock | undefined = network === 'mainnet' ? parsed.mainnet : parsed.testnet;
  const networkPassphrase = block?.networkPassphrase ?? '';
  if (networkPassphrase.length === 0) {
    throw new SdkConfigError(`deployments.json [${network}] has no networkPassphrase`);
  }
  const rpcUrl = block?.networkConfig?.rpcUrl ?? '';
  if (!/^https:\/\//.test(rpcUrl)) {
    if (/^http:\/\//.test(rpcUrl) && opts.allowInsecureRpc === true) {
      // Explicitly allowed; see LoadSdkConfigOptions.allowInsecureRpc.
    } else {
      throw new SdkConfigError(
        `deployments.json [${network}] networkConfig.rpcUrl must be https (got "${rpcUrl}"); ` +
          'pass allowInsecureRpc to accept a plain-http endpoint',
      );
    }
  }
  const kycGateContractId = block?.contracts?.['kyc-gate']?.id ?? '';
  const kycRegistryContractId = block?.contracts?.['kyc-registry']?.id ?? '';
  for (const [name, id] of [
    ['kyc-gate', kycGateContractId],
    ['kyc-registry', kycRegistryContractId],
  ] as const) {
    if (!CONTRACT_ID_RE.test(id)) {
      throw new SdkConfigError(
        `deployments.json [${network}] contracts.${name}.id is not a deployed contract id ` +
          `("${id}"). A mainnet load with nothing deployed fails HERE rather than handing a ` +
          'holder a config that routes credentials to nothing.',
      );
    }
  }

  return {
    network,
    networkPassphrase,
    rpcUrl,
    kycGateContractId,
    kycRegistryContractId,
  };
}
