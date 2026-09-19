/**
 * all; the comments below are the measured evidence, kept because losing them re-invites the
 */

/** A legal Soroban symbol: `[A-Za-z0-9_]`, 1..=32 bytes (`SCSYMBOL_LIMIT`). Asserted rather than
 *  assumed, because it is what makes "byte order" and "JS string order" the same thing below. */
export const SYMBOL_CHARS = /^[A-Za-z0-9_]{1,32}$/;

/**
 * Ascending Soroban symbol order, which is ascending order of the symbol's BYTES — see
 * `proof-scval.ts` for the evidence. Compared with `Buffer.compare` rather than with `<` so the
 * rule is the host's rule and not a coincidence of JavaScript's UTF-16 code-unit comparison.
 */
export function compareSorobanSymbol(a: string, b: string): number {
  if (!SYMBOL_CHARS.test(a)) {
    throw new Error(`"${a}" is not a legal Soroban symbol ([A-Za-z0-9_], 1-32 bytes)`);
  }
  if (!SYMBOL_CHARS.test(b)) {
    throw new Error(`"${b}" is not a legal Soroban symbol ([A-Za-z0-9_], 1-32 bytes)`);
  }
  return Buffer.compare(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'));
}
