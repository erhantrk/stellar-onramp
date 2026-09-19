/**
 * Ambient types for `@digitalbazaar/bbs-signatures@3.1.0` — the package ships JS with no
 * declarations. This is a deliberately minimal copy of the subset scripts/ actually uses;
 * the authoritative version is packages/identity/src/bbs-signatures.d.ts, which is scoped to
 * that package's own compilation and therefore not visible from here.
 *
 * If the 3.1.0 pin ever moves, re-check BOTH files.
 */
declare module '@digitalbazaar/bbs-signatures' {
  export type CiphersuiteId = 'BLS12-381-SHA-256' | 'BLS12-381-SHAKE-256';

  export function sign(opts: {
    secretKey: Uint8Array;
    publicKey?: Uint8Array;
    header: Uint8Array;
    messages: Uint8Array[];
    ciphersuite: CiphersuiteId | unknown;
  }): Promise<Uint8Array>;

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
