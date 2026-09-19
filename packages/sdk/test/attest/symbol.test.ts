/**
 * ScMap symbol ordering — property test plus the KNOWN failure orders measured against the live
 * gate (demo.ts measured block, promoted into proof-scval.ts). The property that matters: for
 * legal Soroban symbols, ascending BYTE order is what the host demands, and `_` sorts ABOVE the
 * digits and capitals (ASCII 0x5F), the reverse of the packed-6-bit-code guess.
 */

import { describe, expect, it } from 'vitest';

import { SYMBOL_CHARS, compareSorobanSymbol } from '../../src/index.js';

/** Legal symbol alphabet, in ASCII byte order. */
const ALPHABET = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz';

describe('compareSorobanSymbol', () => {
  it('orders by BYTES: the known failure pairs from the measured block', () => {
    // [r1_hat, r_hat] was ACCEPTED by the host; [r_hat, r1_hat] was refused with
    // "ScMap was not sorted by key". Same for [_x, 0x] vs [0x, _x].
    expect(compareSorobanSymbol('r1_hat', 'r_hat')).toBeLessThan(0);
    expect(compareSorobanSymbol('r_hat', 'r1_hat')).toBeGreaterThan(0);
    expect(compareSorobanSymbol('0x', '_x')).toBeLessThan(0);
    expect(compareSorobanSymbol('_x', '0x')).toBeGreaterThan(0);
  });

  it('a comparator ranking `_` below the digits would CAUSE the failure it looks like it prevents', () => {
    // Packed-code order would put `_` (code 1) before digits; byte order does not.
    expect(compareSorobanSymbol('_', '0')).toBeGreaterThan(0);
    expect(compareSorobanSymbol('_', 'A')).toBeGreaterThan(0);
    expect(compareSorobanSymbol('_', 'z')).toBeLessThan(0); // 0x5F < 0x7A
  });

  it('is a total order over the legal alphabet (property)', () => {
    for (let i = 0; i < ALPHABET.length; i++) {
      for (let j = 0; j < ALPHABET.length; j++) {
        const a = ALPHABET[i] as string;
        const b = ALPHABET[j] as string;
        const cmp = compareSorobanSymbol(a, b);
        if (a === b) {
          expect(cmp).toBe(0);
          continue;
        }
        // Agrees with raw byte comparison and is antisymmetric over distinct pairs.
        const expected = Math.sign(Buffer.compare(Buffer.from(a), Buffer.from(b)));
        expect(Math.sign(cmp)).toBe(expected);
        expect(Math.sign(compareSorobanSymbol(b, a))).toBe(-expected);
      }
    }
  });

  it('random legal symbols sort identically under the comparator and Buffer.compare (property)', () => {
    // Deterministic PRNG so failures reproduce.
    let seed = 0x2545f491;
    const next = (): number => {
      seed ^= seed << 13;
      seed ^= seed >>> 17;
      seed ^= seed << 5;
      return seed >>> 0;
    };
    for (let round = 0; round < 200; round++) {
      const words: string[] = [];
      for (let w = 0; w < 12; w++) {
        let word = '';
        const len = 1 + (next() % 32);
        for (let c = 0; c < len; c++) word += ALPHABET[next() % ALPHABET.length];
        words.push(word);
      }
      const viaComparator = [...words].sort(compareSorobanSymbol);
      const viaBytes = [...words].sort((a, b) =>
        Buffer.compare(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8')),
      );
      expect(viaComparator).toEqual(viaBytes);
    }
  });

  it('the eight BbsProof field names are emitted in ascending byte order', () => {
    const order = ['a_bar', 'b_bar', 'challenge', 'd', 'e_hat', 'm_hat', 'r1_hat', 'r3_hat'];
    for (let i = 1; i < order.length; i++) {
      expect(compareSorobanSymbol(order[i - 1] as string, order[i] as string)).toBeLessThan(0);
    }
    // And the interesting pair the demo's insertion order happened to list backwards:
    expect(compareSorobanSymbol('m_hat', 'r1_hat')).toBeLessThan(0);
  });

  it.each(['', 'no-dashes!', 'way-more-than-thirty-two-characters-aaaaaaaaaaaaaaaaaaaa', 'ünïcode'])(
    'refuses an illegal symbol (%s)',
    (bad) => {
      expect(() => compareSorobanSymbol(bad, 'ok')).toThrow(/not a legal Soroban symbol/);
      expect(() => compareSorobanSymbol('ok', bad)).toThrow(/not a legal Soroban symbol/);
    },
  );

  it('SYMBOL_CHARS matches exactly the legal shape', () => {
    expect(SYMBOL_CHARS.test('a')).toBe(true);
    expect(SYMBOL_CHARS.test('_')).toBe(true);
    expect(SYMBOL_CHARS.test('A'.repeat(32))).toBe(true);
    expect(SYMBOL_CHARS.test('A'.repeat(33))).toBe(false);
    expect(SYMBOL_CHARS.test('')).toBe(false);
  });
});
