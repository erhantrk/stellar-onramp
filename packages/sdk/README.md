# @stellaronramp/sdk

The holder side: create or connect a passkey smart wallet, keep the credential and its
subject-binding salt, and submit a BBS+ proof to `kyc-gate.attest_bbs` on Stellar.

```bash
npm install @stellaronramp/sdk
```

```ts
import {
  loadSdkConfig, createPasskeyWallet, relayerSubmitter, softwareP256WebAuthn,
  AttestSubmitter, attestBbsArgs, contractCall, ledgerExpiryFor, recordExpiresAtFor,
} from '@stellaronramp/sdk';

const config = loadSdkConfig('testnet');                // from deployments.json, fails closed on empty ids
const wallet = await createPasskeyWallet(
  { rpcUrl: config.rpcUrl, networkPassphrase: config.networkPassphrase, rpId, WebAuthn: softwareP256WebAuthn({ rpId }) },
  relayerSubmitter(passkeyServer),
  { appName: 'Onramp', userName: 'alice' },
);
const submitter = new AttestSubmitter({ server, networkPassphrase: config.networkPassphrase, submitter: payerKeypair });
const args = attestBbsArgs({ subject: wallet.address, issuerId, claimsBitmap, expiresAt, revocationEpoch, revocationIndex, proof, nonceHex, ledgerExpiry });
const landed = await submitter.submit(contractCall(config.kycGateContractId, 'attest_bbs', ...args), 'attest_bbs');
```

`softwareP256WebAuthn` is a test and development authenticator; in a browser, pass the
WebAuthn client from `@simplewebauthn/browser`. The `GatewayClient` covers the gateway's public
documents and `POST /v1/credentials/issue`.

Part of [stellar-onramp](https://github.com/erhantrk/stellar-onramp). MIT.
