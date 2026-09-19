/**
 * harness; this is a COPY, not a move. Typed by return value exactly as the originals were
 * (`ReturnType<typeof nativeToScVal>`), because narrowing to `xdr.ScVal` loses nothing here but
 * keeping the original types keeps the diff against the harness greppable.
 */

import { Address, nativeToScVal, xdr } from '@stellar/stellar-sdk';

export const addrScVal = (a: string): ReturnType<typeof nativeToScVal> =>
  Address.fromString(a).toScVal();
export const u32 = (n: number): ReturnType<typeof nativeToScVal> =>
  nativeToScVal(n, { type: 'u32' });
export const bytesScVal = (b: Uint8Array): ReturnType<typeof nativeToScVal> =>
  nativeToScVal(Buffer.from(b));

/** Re-exported for consumers building ad-hoc reads without reaching into stellar-sdk barrels. */
export { xdr };
