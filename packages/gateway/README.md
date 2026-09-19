# @stellaronramp/gateway

The issuer side of Onramp as a library: turn a KYC provider's status into six boolean claims,
issue a BBS+ credential for a wallet, allocate revocation-list indexes, publish a signed
Bitstring Status List, mint and verify session tokens, and read a subject's claim record from
`kyc-gate`.

```bash
npm install @stellaronramp/gateway
```

```ts
import { deriveClaimSet, issueKycCredential, InMemoryRevocationIndexAllocator } from '@stellaronramp/gateway';

const claims = deriveClaimSet(status, new Date());          // booleans only; PII stays here
const issued = await issueKycCredential({
  ...claims,
  walletAddress,
  issuerSecretKey, issuerPublicKey,
  revocationIndexAllocator: new InMemoryRevocationIndexAllocator(),
  // ...
});
// issued.serialized -> the holder; issued.subjectBindingSalt -> the holder; nothing is kept here
```

The `KycProvider` seam is where a real provider plugs in; `apps/gateway-http` is the HTTP
transport over this library.

Part of [stellar-onramp](https://github.com/erhantrk/stellar-onramp). MIT.
