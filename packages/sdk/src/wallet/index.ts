/**
 * Wallet module barrel — keeps the public surface of src/wallet/ in ONE export list so the
 */
export {
  PASSKEY_WALLET_WASM_HASH,
  WalletError,
  relayerSubmitter,
  createPasskeyWallet,
  connectPasskeyWallet,
  type ConnectPasskeyWalletOptions,
  type CreatedWallet,
  type PasskeyWalletConfig,
  type WalletDeploySubmitter,
} from './wallet.js';

export {
  SoftwareAuthenticatorError,
  softwareP256WebAuthn,
  type SoftwareP256Authenticator,
  type SoftwareP256Options,
} from './software-p256.js';
