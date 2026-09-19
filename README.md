# Onramp

KYC once, prove claims on chain. A person is verified by a KYC provider, receives a BBS+
credential bound to their passkey smart wallet, and the Soroban contract verifies a
selective-disclosure proof of that credential itself and caches the result. Relying contracts
read a boolean; nobody re-collects the passport.

- Live demo: https://stellar-onramp.onrender.com (the free tier sleeps after 15 minutes idle; the first request takes about a minute)
- Packages: [`@stellaronramp/identity`](https://www.npmjs.com/package/@stellaronramp/identity), [`@stellaronramp/gateway`](https://www.npmjs.com/package/@stellaronramp/gateway), [`@stellaronramp/sdk`](https://www.npmjs.com/package/@stellaronramp/sdk)
- Contracts on Stellar testnet: kyc-registry [`CDUYMKOSVKT3Q6GMFTA6Z2J47VK22C5KKJS4ZQJWAQ5HU4OUKGRO5MWM`](https://stellar.expert/explorer/testnet/contract/CDUYMKOSVKT3Q6GMFTA6Z2J47VK22C5KKJS4ZQJWAQ5HU4OUKGRO5MWM) · kyc-gate [`CDKDURQU57L5NVCLQVV3XJN44UECWRKTUDOMG5B7JCUAWYNYYVYWANSE`](https://stellar.expert/explorer/testnet/contract/CDKDURQU57L5NVCLQVV3XJN44UECWRKTUDOMG5B7JCUAWYNYYVYWANSE) · trex-wrap [`CBDKX6ZA6IWRTFWUVRURBEJ6KS4T3XXPJQY2SBIWOWJF5CM2PQSUPNAW`](https://stellar.expert/explorer/testnet/contract/CBDKX6ZA6IWRTFWUVRURBEJ6KS4T3XXPJQY2SBIWOWJF5CM2PQSUPNAW)

## Why

Every service that must know a person is over 18, or not sanctioned, collects and retains the
same identity documents, and every one of those copies is a breach waiting to happen. On chain the
problem inverts: a regulated asset cannot check identity at all without putting identity on the
ledger.

Onramp verifies a person once, turns the result into booleans, and lets the person prove a
boolean to whoever asks. The credential holds no name, date of birth or document number; the proof
reveals only the attributes the relying party needs; the contract verifies the proof
cryptographically and stores the granted claims against the wallet. After that, a check costs a
storage read.

Target users are on-ramps and wallets onboarding people, and issuers of regulated assets that need
an identity verdict at transfer time. The value is a single verification that is reusable,
privacy-preserving, and verifiable by the chain rather than by trusting an operator.

## What the demo does

The partner portal (`/portal`) walks one person through onboarding:

1. Register and sign in.
2. Fill in the KYC wizard. The KYC provider is mocked in this demo; it verifies the answers typed
   in the wizard and returns the verdict chosen on the last step.
3. On the first run, a passkey smart wallet is deployed on testnet for the account. Its contract
   address is the subject of everything that follows.
4. The gateway derives six booleans from the provider status, issues a BBS+ credential over the
   twelve-attribute schema, and returns it with its subject-binding salt. The gateway keeps no copy.
5. The holder derives a selective-disclosure proof revealing only the audit block, `over18` and
   `notSanctioned`, bound to the wallet, the gate contract, the network and a ledger deadline.
6. A scan confirms the date of birth and document number appear nowhere in the presentation, in
   four encodings.
7. `kyc-gate.attest_bbs` verifies the proof inside the contract (BLS12-381 pairing, about 105M
   instructions) and writes the claim record.
8. The record is read back. The dashboard reads it again from the browser through public
   testnet RPC, with the server out of the path.

## Architecture

```
 browser (portal)                 demo server (scripts/demo-web.ts)                 Stellar testnet
 ───────────────                  ───────────────────────────────────                ───────────────
 register / wizard  ──/api──▶  onboarding pipeline (scripts/demo/)
                                   │  POST /v1/session ─────▶ gateway-http (loopback)
                                   │  mock KYC verdict        │ session store
                                   │  POST /v1/credentials/issue ─▶ @stellaronramp/gateway
                                   │        ◀─ credential + salt     (claims, BBS+ issue,
                                   │  holder store (credential, salt) status list)
                                   │  prove()  ◀── @stellaronramp/identity
                                   │  attest_bbs ──── @stellaronramp/sdk ──────▶ kyc-gate ──▶ kyc-registry
                                   │                                              │ verify pairing
                                   │                                              │ write claim record
 dashboard ◀─ simulateTransaction (check, claim_record) ──────────────────────────▶ kyc-gate
                                                                     trex-wrap ──▶ kyc-gate.check
```

## Components

| Path | Responsibility |
|---|---|
| `contracts/kyc-registry` | Issuer allowlist: issuer id → uncompressed G2 public key, with expiry and revocation. |
| `contracts/kyc-gate` | Verifies a BBS+ proof on chain (`attest_bbs`), caches a claim record per subject, answers `check(subject, claim_bit)` and `claim_record(subject)`, admin `revoke`, `set_admin`, `upgrade`. |
| `trex/trex-wrap` | SEP-57 `IdentityVerifier` adapter over `kyc-gate.check`, so a regulated-asset transfer can require an on-chain verdict. |
| `packages/identity` | BBS+ credential library: schema, issue, prove, verify, presentation binding, Bitstring Status List. |
| `packages/gateway` | Issuer library: claim derivation, credential issuance, revocation-index allocation, status-list publishing, session JWTs, claim-record reads. |
| `packages/sdk` | Holder library: passkey wallet create/connect, credential custody, `attest_bbs` argument encoding and submission, gateway client. |
| `apps/gateway-http` | The gateway over HTTP: `POST /v1/session`, `POST /v1/credentials/issue`, `GET /v1/status-list/{issuer_id}`, issuer documents, health. Every seam is injected. |
| `apps/web` | The landing page and the partner portal. |
| `scripts/demo-web.ts`, `scripts/demo/`, `scripts/onboard/` | The demo server: boots the gateway on loopback, serves the portal, runs the pipeline, keeps accounts, sessions and holder credentials in a data directory. |

## Stellar integrations and protocols

- Soroban contracts (soroban-sdk 27 for the registry and gate, 26 for the SEP-57 adapter, which
  composes across the wasm ABI boundary), built for `wasm32v1-none`.
- BLS12-381 host functions (CAP-0059) for the in-contract BBS+ proof verification; the verifier is
  written directly against them.
- Passkey smart wallets: OpenZeppelin `passkey-kit`, deployed through the Channels relayer, with
  WebAuthn P-256 signers.
- SEP-57 `IdentityVerifier` for regulated assets.
- Stellar RPC `simulateTransaction` from the browser, so a viewer verifies the record without the
  demo server.
- Every deployed wasm is fetched back with `stellar contract fetch` and compared byte for byte
  with the local build; hashes and deploy transactions are in `deployments.json`.

## Key design decisions

- **Verify once, then read.** A proof verification costs about 105M instructions and the network
  caps a ledger at 580M, so the proof is verified once at onboarding and every later check reads
  the cached record.
- **Booleans, not range proofs.** BBS+ cannot express "born before 2008" as a predicate, so
  `over18` is derived off-chain by the issuer and signed as an attribute. The credential has no
  slot for the source data.
- **The proof binds to the subject on chain.** The presentation header is derived inside the
  contract from the wallet address, a nonce, the ledger deadline, the contract and the network.
  A proof cannot be replayed for another wallet, another contract, another network, or after its
  deadline; the nonce is consumed on use.
- **Revocation.** An admin revocation writes a tombstone and advances the subject's epoch, so
  every proof derived before it is dead. The issuer also publishes a signed Bitstring Status List;
  the record carries the credential's index in it as an audit link.
- **Subject binding.** The credential commits to `sha256(wallet ‖ salt)`; the salt is held by the
  holder and disclosed at the gate.
- **The KYC provider is mocked.** The mock verifies the wizard's answers and applies the chosen
  verdict; the `KycProvider` seam is where a real provider plugs in.
- **The demo authenticator is software.** The portal deploys each wallet with a server-side P-256
  key that is discarded after deployment; in a browser the passkey is the person's own.
- **Testnet only.** The issuer seed is fixed and the deployer pays for attestations.

## Technical challenges

- **Pairing cost inside the transaction budget.** Verifying against a pure-wasm pairing library
  measured over twice the per-transaction budget; the verifier is written against the host
  functions instead, and the design caches the result so the cost is paid once.
- **Reproducing the off-chain library bit for bit.** The contract mirrors the generator
  derivation, domain calculation and hash-to-scalar of the BBS+ library that issues the
  credentials; frozen test vectors pin both sides to each other.
- **Uncompressed points.** The host offers no point decompression, so the SDK decompresses the
  proof's G1 points before submission and the contract rejects the compression flag.
- **Ledger time versus wall time.** Expiry and nonce lifetimes are ledger sequences; the
  temporary-entry TTL ceiling is `max_entry_ttl - 1`, and the proof freshness window is kept inside
  the nonce tombstone's minimum lifetime so a proof can never outlive the entry that stops its
  replay.
- **Headless wallet deployment.** The relayer needs a server-held key, and `createWallet` only
  builds the transaction; the SDK submits it and then verifies on chain that the passkey is a live
  signer before returning the address.
- **No personal data in any byte.** The demo scans the serialised presentation for the date of
  birth and document number in four encodings, and checks that a value the proof does disclose is
  found, so a clean scan cannot be vacuous.

## How this compares

Other Stellar identity work falls into two groups. Registry designs store a record that a trusted
issuer or verifier key wrote, and relying contracts trust that key. Proof designs verify a
cryptographic proof inside a Soroban contract. Onramp is in the second group and uses BBS+ over
BLS12-381, which gives selective disclosure from one signature without a per-claim circuit or a
trusted setup.

| Project | What goes on chain | Who a contract must trust | Personal data |
|---|---|---|---|
| [Stellar Attestation Service](https://github.com/Soroban-Eas/soroban-sas) | Attestation record with an arbitrary data payload | The attester account | Whatever the attester puts in the payload |
| [soroban-attestation-registry](https://github.com/VedantMadane/soroban-attestation-registry) | (issuer, subject, credential name) → valid / revoked | The issuer address | Addresses and credential names |
| [web3-suite identity contracts](https://github.com/sudo-robi/web3-suite-identity-contracts) | KYC level, verifier, expiry, hash of the documents | Admin-registered verifier keys | Document hash on chain |
| [stellar-did-credit](https://github.com/cybermax4200/stellar-did-credit) | Hash of each credential, DID document CID, credit score | Admin-curated issuer registry | Credential body on IPFS; score public |
| [SEP-57 reference IdentityVerifier](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0057.md) | Identity registry and stored claim signatures, country per wallet | Registry of trusted claim issuers | Claim data and country stored on chain |
| [StellarCred](https://github.com/ToluLabs/StellarCred) | "verified until T" flag after an in-contract UltraHonk proof (BN254) | Issuer secp256k1 key plus a verification key per claim type | Commitment stays off chain |
| [stellar-zkident](https://github.com/stellar-zklab/stellar-zkident) | Groth16 public inputs after an in-contract BN254 pairing check; reputation SBTs | A Groth16 verification key per circuit | Attributes off chain; Merkle path links address to credential type |
| Onramp | Claim record after one in-contract BBS+ verification: booleans such as `over18`, `notSanctioned`, bound to the wallet | The issuer's BBS+ public key and the pairing check | None in the credential, the proof or the chain |

Sources are each project's repository or the SEP text as read on 2026-09-19.

## Run it locally

Requirements: node 22, rustc 1.91+, stellar CLI 27, the `wasm32v1-none` target, a funded testnet
key named `stellaronramp-dev` in the stellar CLI keystore.

```bash
npm install
npm run build
npm test                       # TypeScript suites
npm run contracts:test         # builds the wasm, then cargo test in both workspaces
npm run demo:web               # http://127.0.0.1:8788/portal
```

Deploy the contracts (registry, gate, adapter) and register the demo issuer:

```bash
cd contracts && stellar contract build
stellar contract deploy --wasm target/wasm32v1-none/release/kyc_registry.wasm --source stellaronramp-dev --network testnet
stellar contract invoke --id <REGISTRY> --source stellaronramp-dev --network testnet -- init --admin <ADMIN_G>
stellar contract invoke --id <REGISTRY> --source stellaronramp-dev --network testnet -- register_issuer --issuer_id <ISSUER_ID_HEX> --pubkey_g2 <G2_HEX_192B> --valid_until 0
stellar contract deploy --wasm target/wasm32v1-none/release/kyc_gate.wasm --source stellaronramp-dev --network testnet
stellar contract invoke --id <GATE> --source stellaronramp-dev --network testnet -- init --admin <ADMIN_G> --registry <REGISTRY>
cd ../trex && stellar contract build
stellar contract deploy --wasm target/wasm32v1-none/release/trex_wrap.wasm --source stellaronramp-dev --network testnet -- --owner <ADMIN_G> --kyc_gate <GATE> --required_bitmap 5
```

Put the ids in `deployments.json`; the config loaders fail closed while they are empty.

## Deploy

The demo server is one Node process with file-backed state, packaged by the `Dockerfile` and
described for Render in `render.yaml` (Docker runtime, `/healthz`). Environment:

| Variable | Meaning |
|---|---|
| `STELLARONRAMP_DEPLOYER_SECRET` | Secret key of the `testnet.deployer` in `deployments.json`; pays for attestations. Testnet only. |
| `PORTAL_RP_ID` | The public hostname, used as the WebAuthn relying-party id. |
| `PORTAL_DATA_DIR` | Where accounts, sessions, credentials and the status list are kept (`/data` in the image). |
| `HOST`, `PORT`, `GATEWAY_PORT` | Bind address and ports; the gateway stays on loopback. |
| `PORTAL_SECURE_COOKIES` | `1` behind https. |
| `PORTAL_PREBUILT` | `1` in the image: assert `dist/` exists instead of building at boot. |

Reset a portal password with `npx tsx scripts/onboard/reset-password.ts <email> <new-password>`
and restart the server.

## Packages on npm

```bash
npm install @stellaronramp/identity   # BBS+ credentials: issue, prove, verify, status list
npm install @stellaronramp/gateway    # issuer side: claim derivation, credential issuance
npm install @stellaronramp/sdk        # holder side: passkey wallet, custody, attest_bbs submission
```

## License

MIT
