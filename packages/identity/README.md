# @stellaronramp/identity

BBS+ credentials for Stellar: issue a credential over twelve schema attributes, derive a
selective-disclosure proof bound to a wallet, contract, network and ledger deadline, verify it,
and revoke it through a W3C Bitstring Status List.

```bash
npm install @stellaronramp/identity
```

```ts
import { generateIssuerKeyPair, issue, prove, gateOnrampPredicate, verify } from '@stellaronramp/identity';

const issuer = await generateIssuerKeyPair(seed);
const credential = await issue({ ...claims, schemaVersion: '1' }, issuer.secretKey);
const proof = await prove(credential, gateOnrampPredicate(), {
  nonce, walletAddress, contractId, networkPassphrase, ledgerExpiry,
});
await verify(proof, issuer.publicKey, binding, { expectedClaims: { over18: true } });
```

The schema has no slot for a name, a date of birth or a document number; claims are booleans
derived off-chain. The proof format and generator derivation match the on-chain verifier in
`contracts/kyc-gate`, so a proof this library derives is what `attest_bbs` checks.

Part of [stellar-onramp](https://github.com/erhantrk/stellar-onramp). MIT.
