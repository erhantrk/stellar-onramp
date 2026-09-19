/**
 * The portal's WALLET MINTER — a real passkey smart wallet, deployed on testnet, one per account.
 *
 * WHY. `attest_bbs` binds the ClaimRecord to a subject contract address. A random `C…` string
 * satisfies the contract (there is no `subject.require_auth()` on the attest path), but it is a
 * subject that does not exist: nothing can ever act as it, so the on-chain record is bound to a
 * ghost. The portal deploys the same OpenZeppelin passkey wallet the SDK live check proves
 * contract is deployed through the free Channels relayer, and ownership is verified on chain by
 * `connectPasskeyWallet` before the address is handed back.
 *
 * WHAT IS STILL DEV-GRADE, SAID PLAINLY. The authenticator is `softwareP256WebAuthn()` — a
 * server-side software P-256 key, because this dev server has no browser to run WebAuthn in and
 * bundles nothing. Its private key is DISCARDED after the deployment: the portal keeps only the
 * credential id and the deploy tx, so the server never becomes a custodian of the holder's
 * signing key. The cost of that choice is that the demo wallet cannot sign later; in production
 * the passkey lives in the person's browser/authenticator and the wallet is fully theirs. The
 * subject on chain is real either way, which is the point of this module.
 *
 * The Channels relayer key is minted lazily ONCE per process from `GET …/testnet/gen` (free, no
 * signup) and cached; it is a bearer secret carrying a fee budget and is never logged.
 */

import { createPasskeyWallet, relayerSubmitter, softwareP256WebAuthn } from '@stellaronramp/sdk';

import type { EmitStep } from '../demo/demo-flow.js';

export interface PortalWalletConfig {
  readonly rpcUrl: string;
  readonly networkPassphrase: string;
  /** WebAuthn relying-party id the software authenticator answers for. */
  readonly rpId: string;
  /** `https://channels.openzeppelin.com/testnet`. */
  readonly relayerBaseUrl: string;
  readonly explorerBase: string;
}

export interface PortalWallet {
  /** The deployed wallet contract address (`C…`), ownership-verified on chain. */
  readonly address: string;
  /** base64url passkey credential id the wallet was deployed with. */
  readonly keyId: string;
  /** The deployment transaction hash. */
  readonly deployTxHash: string;
}

export interface PortalWalletMinter {
  create(args: { userName: string; emit: EmitStep }): Promise<PortalWallet>;
}

export function portalWalletMinter(config: PortalWalletConfig): PortalWalletMinter {
  let relayerKey: Promise<string> | undefined;

  const relayerApiKey = (): Promise<string> => {
    relayerKey ??= (async () => {
      const res = await fetch(`${config.relayerBaseUrl}/gen`, { signal: AbortSignal.timeout(15_000) });
      if (!res.ok) {
        throw new Error(`Channels relayer key mint failed: HTTP ${res.status} from ${config.relayerBaseUrl}/gen`);
      }
      const body = (await res.json()) as { apiKey?: unknown };
      if (typeof body.apiKey !== 'string' || body.apiKey.length === 0) {
        throw new Error('Channels relayer key mint returned no apiKey');
      }
      return body.apiKey;
    })();
    // A failed mint must not poison every later wallet: drop the cached rejection.
    relayerKey.catch(() => {
      relayerKey = undefined;
    });
    return relayerKey;
  };

  return {
    async create({ userName, emit }): Promise<PortalWallet> {
      const apiKey = await relayerApiKey();
      // `passkey-kit/server` refuses to be browser-bundled and holds the relayer secret — hence a
      // dynamic import here, on the server, next to the only code that needs it.
      const { PasskeyServer } = await import('passkey-kit/server');
      const relayer = new PasskeyServer({
        networkPassphrase: config.networkPassphrase,
        rpcUrl: config.rpcUrl,
        relayer: { baseUrl: config.relayerBaseUrl, apiKey },
      });
      // KNOWN GAP: `createPasskeyWallet` submits the deployment and THEN verifies ownership on
      // chain. An RPC failure between the two throws after the relayer has paid, and since the
      // address is only persisted by the caller on success, the next run deploys a second wallet
      // deployment; a production minter would persist the predicted address before submitting.
      const wallet = await createPasskeyWallet(
        {
          rpcUrl: config.rpcUrl,
          networkPassphrase: config.networkPassphrase,
          rpId: config.rpId,
          WebAuthn: softwareP256WebAuthn({ rpId: config.rpId }),
        },
        relayerSubmitter(relayer),
        { appName: 'StellarOnramp', userName },
      );
      await emit({
        id: 'wallet',
        title: 'Deploy the passkey smart wallet',
        detail:
          'Registered a WebAuthn P-256 credential, deployed an OpenZeppelin passkey wallet contract ' +
          'through the Channels relayer, and verified on chain that the credential is a live signer ' +
          'on it. This contract address is the subject every credential and on-chain record binds ' +
          'to. Dev note: the authenticator here is a server-side software key, discarded after ' +
          'deployment; in production it is the passkey in your browser.',
        status: 'ok',
        txHash: wallet.deployTxHash,
        explorerUrl: `${config.explorerBase}/tx/${wallet.deployTxHash}`,
        data: { wallet: wallet.address, keyId: wallet.keyId.slice(0, 12) + '…' },
      });
      return { address: wallet.address, keyId: wallet.keyId, deployTxHash: wallet.deployTxHash };
    },
  };
}
