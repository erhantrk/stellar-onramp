/**
 * Passkey smart-wallet creation and connection: the holder's entry point, returning the wallet
 * contract address every credential and on-chain record is bound to.
 *
 * `createPasskeyWallet` does three things in order: builds the deployment through passkey-kit's
 * `createWallet`, submits it through the injected submitter (the Channels relayer in practice),
 * and then `connectWallet` verifies on chain that the passkey is a live signer on the resulting
 * contract before the address is returned. The predicted address is validated as a C-strkey
 * before anything is submitted.
 */

import { PasskeyKit } from 'passkey-kit';
import { PasskeyServer } from 'passkey-kit/server';
import type {
  ConnectWalletResult,
  CreateWalletResult,
  TransactionResult,
} from 'passkey-kit';

import type { KitWebAuthnClient, PasskeyKitOptions } from './kit-types.js';

export class WalletError extends Error {
  override readonly name = 'WalletError';
}

/**
 * The canonical passkey-kit smart-wallet WASM hash on testnet and mainnet (passkey-kit 0.16.3+,
 * soroban-sdk 27). A `createWallet` simulation against this hash succeeds on testnet.
 */
export const PASSKEY_WALLET_WASM_HASH = '502ea4e7bdb3ea99880941f1d35ceb67fb598692c0bb40f842ef9c9f17d58b58';

const STRKEY_C_RE = /^C[A-Z2-7]{55}$/;

/** Configuration for {@link createPasskeyWallet} / {@link connectPasskeyWallet}. */
export interface PasskeyWalletConfig {
  readonly rpcUrl: string;
  readonly networkPassphrase: string;
  /** Defaults to {@link PASSKEY_WALLET_WASM_HASH}. Overriding it changes every derived address. */
  readonly walletWasmHash?: string;
  /**
   * WebAuthn Relying Party id (a domain), e.g. "example.com". Passed through to the kit, which
   * hashes it into the authenticator data and defaults it to the browser origin when omitted.
   * The software authenticator in this package defaults to the same value, so tests that use it
   * need not set this.
   */
  readonly rpId?: string;
  /**
   * The authenticator implementation. REQUIRED: there is no default, deliberately. In Node there
   * is no `navigator.credentials`; in a browser the app passes `@simplewebauthn/browser`'s
   * `startRegistration`/`startAuthentication` client, which is the production path — UNTESTED in
   * headless-testable. For tests/dev use `softwareP256WebAuthn()` from this package.
   */
  readonly WebAuthn: KitWebAuthnClient;
}

/**
 * The deployment-carrier submitter seam. `PasskeyServer.send` needs a relayer API key and is
 * therefore server-only (passkey-kit/server refuses to be browser-bundled); rather than making
 * every SDK consumer construct one inline, they hand us ANYTHING that can submit the signed
 * carrier. Production wires `relayerSubmitter(...)`; tests inject a fake.
 */
export interface WalletDeploySubmitter {
  /** Submit the base64 XDR carrier. Resolves with the tx hash; throws WalletError on refusal. */
  submit(signedTxBase64: string): Promise<string>;
}

/**
 * Adapter from `PasskeyServer` (which holds the Channels relayer key) to the submitter seam.
 * The server URL is `https://channels.openzeppelin.com/testnet`; keys are FREE — minted at
 * `GET .../gen` with no signup or payment (measured: HTTP 201 + JSON body). Store the key
 * server-side; it is a bearer secret carrying a fee budget.
 */
export function relayerSubmitter(server: PasskeyServer): WalletDeploySubmitter {
  return {
    async submit(signedTxBase64: string): Promise<string> {
      // `send` NEVER throws for expected relayer/on-chain failures — it returns the union. Only
      // transport-level surprises throw; both paths land in WalletError below.
      const result: TransactionResult = await server.send(signedTxBase64);
      if (!result.success) {
        throw new WalletError(
          `wallet deployment refused by the relayer: ${result.error.message} ` +
            `(code ${String(result.error.code)})`,
          { cause: result.error },
        );
      }
      if (result.hash.length === 0) {
        throw new WalletError('wallet deployment submitted but no transaction hash came back');
      }
      return result.hash;
    },
  };
}

/** A created, deployed and VERIFIED wallet. */
export interface CreatedWallet {
  readonly address: string;
  /** base64url credential id of the creating passkey. Keep it: connectWallet resolves by it. */
  readonly keyId: string;
  /** The deploy transaction hash on the funded network. */
  readonly deployTxHash: string;
  /** The connected kit — usable for later signing operations. */
  readonly kit: PasskeyKit;
}

function newKit(config: PasskeyWalletConfig): PasskeyKit {
  // Built imperatively rather than with `rpId: config.rpId` because `exactOptionalPropertyTypes`
  // forbids assigning an explicit `undefined` to an optional property.
  const kitConfig: PasskeyKitOptions = {
    rpcUrl: config.rpcUrl,
    networkPassphrase: config.networkPassphrase,
    walletWasmHash: config.walletWasmHash ?? PASSKEY_WALLET_WASM_HASH,
    WebAuthn: config.WebAuthn,
  };
  if (config.rpId !== undefined) kitConfig.rpId = config.rpId;
  return new PasskeyKit(kitConfig);
}

/**
 * Register a passkey, submit the wallet deployment, and verify the result on chain.
 *
 * Ordering is load-bearing: the predicted address is validated as a C-strkey BEFORE submission
 * (an invalid prediction means the wasm-hash/config pair is wrong — cheaper to learn now than
 * after the relayer spends its budget), and `connectWallet` runs AFTER submission so the returned
 * address is not merely predicted but OWNERSHIP-VERIFIED (the keyId resolves to a live signer on
 * that contract — passkey-kit closes the unverified-reverse-lookup hole at this step).
 */
export async function createPasskeyWallet(
  config: PasskeyWalletConfig,
  submitter: WalletDeploySubmitter,
  options: { readonly appName: string; readonly userName: string },
  /**
   * through the pre-submit C-strkey guard without faking passkey-kit's signing internals —
   * the guard fires BEFORE the submitter and BEFORE connect, so a two-line stub covers exactly
   * the guard. TEST/DEV ONLY, like softwareP256WebAuthn; production callers never pass it.
   */
  kitOverride?: Pick<PasskeyKit, 'createWallet'>,
): Promise<CreatedWallet> {
  let created: CreateWalletResult;
  try {
    const kit = kitOverride ?? newKit(config);
    created = await kit.createWallet(options.appName, options.userName);
  } catch (cause) {
    throw new WalletError(
      `wallet registration/deployment-build failed: ${String((cause as Error)?.message ?? cause)}`,
      { cause },
    );
  }
  if (!STRKEY_C_RE.test(created.contractId)) {
    throw new WalletError(
      `createWallet predicted "${created.contractId}", which is not a C-strkey — refusing to ` +
        'submit a deployment toward an unusable address',
    );
  }
  const deployTxHash = await submitter.submit(created.signedTx);

  // Verify on chain before reporting success. A failed connect after a successful submit is
  // reported AS THAT (the wallet exists; ownership verification failed) — swallowing it into a
  // generic failure would invite callers to re-create and orphan the first wallet.
  const connected = await connectPasskeyWallet(config, { keyId: created.keyIdBase64 });
  return {
    address: connected.address,
    keyId: created.keyIdBase64,
    deployTxHash,
    kit: connected.kit,
  };
}

/** Options for {@link connectPasskeyWallet}. Exactly one resolution input today: the keyId. */
export interface ConnectPasskeyWalletOptions {
  readonly keyId: string;
}

/**
 * Connect to an EXISTING wallet: resolve the address from the credential id, then verify
 * ownership with a plain RPC ledger read (no indexer required — Mercury is optional and keyless
 * but never load-bearing here). Throws WalletError (wrapping passkey-kit's WalletOwnershipError)
 * if the keyId is not a live signer on the resolved contract.
 */
export async function connectPasskeyWallet(
  config: PasskeyWalletConfig,
  options: ConnectPasskeyWalletOptions,
): Promise<{ readonly address: string; readonly kit: PasskeyKit }> {
  let connected: ConnectWalletResult;
  const kit = newKit(config);
  try {
    connected = await kit.connectWallet({ keyId: options.keyId });
  } catch (cause) {
    throw new WalletError(
      `connectWallet failed for keyId ${options.keyId.slice(0, 12)}…: ` +
        `${String((cause as Error)?.message ?? cause)}`,
      { cause },
    );
  }
  if (!STRKEY_C_RE.test(connected.contractId)) {
    throw new WalletError(`connectWallet resolved a non-C-strkey address: ${connected.contractId}`);
  }
  return { address: connected.contractId, kit };
}
