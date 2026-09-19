/**
 * Ambient types for `@digitalbazaar/bbs-signatures@3.1.0`, which ships JS only (no .d.ts).
 * Signatures transcribed from the installed module's live function sources — see
 * docs/research/identity-credentials-sdk.md §5.1, which printed them from the runtime objects.
 */
declare module '@digitalbazaar/bbs-signatures' {
  export const CIPHERSUITES: {
    readonly BLS12381_SHAKE256: unknown;
    readonly BLS12381_SHA256: unknown;
  };

  export type CiphersuiteId = 'BLS12-381-SHA-256' | 'BLS12-381-SHAKE-256';

  export function generateKeyPair(opts: {
    seed?: Uint8Array;
    ciphersuite: CiphersuiteId | unknown;
  }): Promise<{ secretKey: Uint8Array; publicKey: Uint8Array }>;

  export function secretKeyToPublicKey(opts: {
    secretKey: Uint8Array;
    ciphersuite: CiphersuiteId | unknown;
  }): Promise<Uint8Array>;

  export function sign(opts: {
    secretKey: Uint8Array;
    publicKey?: Uint8Array;
    header: Uint8Array;
    messages: Uint8Array[];
    ciphersuite: CiphersuiteId | unknown;
  }): Promise<Uint8Array>;

  export function verifySignature(opts: {
    publicKey: Uint8Array;
    signature: Uint8Array;
    header: Uint8Array;
    messages: Uint8Array[];
    ciphersuite: CiphersuiteId | unknown;
  }): Promise<boolean>;

  /**
   * NOTE: there is no `bounds` / `range` / `predicate` parameter and there never will be —
   */
  export function deriveProof(opts: {
    publicKey: Uint8Array;
    signature: Uint8Array;
    header: Uint8Array;
    messages: Uint8Array[];
    presentationHeader: Uint8Array;
    disclosedMessageIndexes: number[];
    ciphersuite: CiphersuiteId | unknown;
  }): Promise<Uint8Array>;

  export function verifyProof(opts: {
    publicKey: Uint8Array;
    proof: Uint8Array;
    header: Uint8Array;
    presentationHeader: Uint8Array;
    disclosedMessages: Uint8Array[];
    disclosedMessageIndexes: number[];
    ciphersuite: CiphersuiteId | unknown;
  }): Promise<boolean>;
}
