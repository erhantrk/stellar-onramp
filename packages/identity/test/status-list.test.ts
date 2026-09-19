/**
 * W3C Bitstring Status List v1.0 — decoding.
 *
 * Every expected value in this file is derived from the SPEC TEXT, quoted in the comment above
 * the assertion, not from our own encoder. Where a list has to be built, it is built here by hand
 * with Node's `Buffer.toString('base64url')` and the platform `CompressionStream`, deliberately
 * bypassing `base64urlEncode`/`encodeStatusList` so an encoder/decoder pair that agrees with
 * itself and disagrees with the spec cannot pass.
 *
 * Spec: https://www.w3.org/TR/vc-bitstring-status-list/
 */

import { describe, expect, it } from 'vitest';

import {
  MAX_STATUS_LIST_BYTES,
  MINIMUM_STATUS_LIST_BYTES,
  MINIMUM_STATUS_LIST_ENTRIES,
  MULTIBASE_BASE64URL_NOPAD_PREFIX,
  StatusListError,
  base64urlDecode,
  base64urlEncode,
  bitAt,
  decodeStatusList,
  encodeStatusList,
  isStatusSet,
  multibaseDecode,
  statusAt,
  type BitstringStatusList,
} from '../src/index.js';


/**
 * The literal `encodedList` from the spec's own worked examples (§2.2 Example 3, and every
 * example in Appendix A). Pasted byte for byte from the Recommendation.
 */
const SPEC_EXAMPLE_ENCODED_LIST =
  'uH4sIAAAAAAAAA-3BMQEAAADCoPVPbQwfoAAAAAAAAAAAAAAAAAAAAIC3AYbSVKsAQAAA';

/* -------------------------------------------------------------------------- */
/* Independent list construction — no code from src/status-list.ts             */
/* -------------------------------------------------------------------------- */

async function gzipRaw(bytes: Uint8Array): Promise<Uint8Array> {
  const cs = new CompressionStream('gzip');
  const w = cs.writable.getWriter();
  void w.write(bytes);
  void w.close();
  const chunks: Uint8Array[] = [];
  const r = cs.readable.getReader();
  for (;;) {
    const { done, value } = await r.read();
    if (done) break;
    if (value !== undefined) chunks.push(value);
  }
  return new Uint8Array(Buffer.concat(chunks));
}

/**
 * "the first index, with a value of zero (0), is located at the left-most bit in the bitstring".
 * The left-most bit of a byte is 0x80, hence `0x80 >> (i & 7)`.
 * base64url comes from Node's Buffer, not from our encoder.
 */
async function handBuiltList(
  statusPurpose: string,
  set: readonly number[],
  entries = MINIMUM_STATUS_LIST_ENTRIES,
  statusSize?: number,
): Promise<BitstringStatusList> {
  const size = statusSize ?? 1;
  const bits = new Uint8Array((entries * size) / 8);
  for (const i of set) {
    for (let b = 0; b < size; b++) {
      const p = i * size + b;
      bits[p >> 3] = (bits[p >> 3] as number) | (0x80 >> (p & 7));
    }
  }
  const encodedList = `u${Buffer.from(await gzipRaw(bits)).toString('base64url')}`;
  if (statusSize === undefined) return { statusPurpose, encodedList };
  // §2.2: "statusMessage ... MUST be present if statusSize is greater than 1", "the length of
  // which MUST equal the number of possible status messages indicated by statusSize". Enforced
  // since R5, so a hand-built multi-bit fixture has to conform or it is rejected before the
  // property under test is ever reached. Built here rather than by encodeStatusList on purpose:
  // this helper's whole job is to be an independent oracle.
  const statusMessage = Array.from({ length: 2 ** size }, (_, v) => ({
    status: `0x${v.toString(16)}`,
    message: v === 0 ? 'valid' : `code ${v}`,
  }));
  return { statusPurpose, encodedList, statusSize, statusMessage };
}

/* -------------------------------------------------------------------------- */

describe('multibase / base64url layer', () => {
  it('demands the "u" header — cid-1.0 §2.4: "u | base-64-url-no-pad"', () => {
    expect(MULTIBASE_BASE64URL_NOPAD_PREFIX).toBe('u');
    expect(SPEC_EXAMPLE_ENCODED_LIST[0]).toBe('u');
    // "z" is base58-btc in the same table; a list that used it must not be silently accepted.
    expect(() => multibaseDecode(`z${SPEC_EXAMPLE_ENCODED_LIST.slice(1)}`)).toThrow(StatusListError);
    expect(() => multibaseDecode(SPEC_EXAMPLE_ENCODED_LIST.slice(1))).toThrow(StatusListError);
    expect(() => multibaseDecode('')).toThrow(StatusListError);
  });

  it('decodes base64url identically to Node Buffer, and rejects non-canonical input', () => {
    const body = SPEC_EXAMPLE_ENCODED_LIST.slice(1);
    expect(Buffer.from(base64urlDecode(body)).toString('hex')).toBe(
      Buffer.from(body, 'base64url').toString('hex'),
    );
    // "(with no padding)" — §2.2. Padding, standard-base64 alphabet and whitespace are all out.
    expect(() => base64urlDecode(`${body}=`)).toThrow(StatusListError);
    expect(() => base64urlDecode('a+/b')).toThrow(StatusListError);
    expect(() => base64urlDecode('AA A')).toThrow(StatusListError);
    expect(() => base64urlDecode('A')).toThrow(StatusListError);
    // Non-zero trailing bits would let two strings decode to the same bytes.
    expect(() => base64urlDecode('AB')).toThrow(/non-canonical/);
    expect(base64urlDecode('AA')).toEqual(Uint8Array.of(0));
  });

  it('round-trips every byte value through encode/decode', () => {
    for (let len = 0; len < 8; len++) {
      const bytes = Uint8Array.from({ length: len }, (_, i) => (i * 37 + 11) & 0xff);
      expect(base64urlDecode(base64urlEncode(bytes))).toEqual(bytes);
    }
    const all = Uint8Array.from({ length: 256 }, (_, i) => i);
    expect(base64urlDecode(base64urlEncode(all))).toEqual(all);
    expect(base64urlEncode(all)).not.toContain('=');
  });
});

describe('bitstring encoding — the status-list format', () => {
  it('index 0 is the LEFT-MOST bit of byte 0, i.e. mask 0x80 — NOT 0x01', () => {
    // §2.2 (normative): "The bitstring MUST be encoded such that the first index, with a value of
    // zero (0), is located at the left-most bit in the bitstring and the last index, with a value
    // of one less than the length of the bitstring (bitstring_length - 1), is located at the
    // right-most bit in the bitstring."
    const bits = new Uint8Array(2);
    bits[0] = 0x80;
    expect(bitAt(bits, 0)).toBe(1);
    for (let i = 1; i < 16; i++) expect(bitAt(bits, i)).toBe(0);

    // ...and the right-most bit of byte 0 is index 7, not index 0.
    const right = new Uint8Array(2);
    right[0] = 0x01;
    expect(right[0]).toBe(0x01);
    expect(bitAt(right, 7)).toBe(1);
    expect(bitAt(right, 0)).toBe(0);

    // Byte boundaries: index 8 is the left-most bit of byte 1.
    const second = new Uint8Array(2);
    second[1] = 0x80;
    expect(bitAt(second, 8)).toBe(1);
    expect(bitAt(second, 15)).toBe(0);
  });

  it('refuses a bit index outside the bitstring', () => {
    const bits = new Uint8Array(2);
    expect(() => bitAt(bits, 16)).toThrow(StatusListError);
    expect(() => bitAt(bits, -1)).toThrow(StatusListError);
    expect(() => bitAt(bits, 1.5)).toThrow(StatusListError);
  });

  it('places each set index at 0x80 >> (i & 7) of byte (i >> 3), end to end', async () => {
    // §7.1: "if a bitstring is 131,072 bits in size (16KB), the first index will be 0, and the
    // last index will be 131,071." Check both ends and a byte-boundary crossing.
    for (const [index, byte, mask] of [
      [0, 0, 0x80],
      [1, 0, 0x40],
      [7, 0, 0x01],
      [8, 1, 0x80],
      [MINIMUM_STATUS_LIST_ENTRIES - 1, MINIMUM_STATUS_LIST_BYTES - 1, 0x01],
    ] as const) {
      const decoded = await decodeStatusList(await encodeStatusList({
        statusPurpose: 'revocation',
        set: [index],
      }));
      expect(decoded.bits[byte]).toBe(mask);
      expect(statusAt(decoded, index)).toBe(1);
      expect(decoded.bits.reduce((a, b) => a + b, 0)).toBe(mask); // nothing else got set
    }
  });
});

describe("the spec's own example encodedList", () => {
  it('decodes to 16,384 bytes of zeroes — 131,072 unrevoked entries', async () => {
    const decoded = await decodeStatusList({
      statusPurpose: 'revocation',
      encodedList: SPEC_EXAMPLE_ENCODED_LIST,
    });
    // §2.2: "The uncompressed bitstring MUST be at least 16KB in size."
    expect(decoded.bits.length).toBe(16_384);
    expect(decoded.bits.length).toBe(MINIMUM_STATUS_LIST_BYTES);
    expect(decoded.bitLength).toBe(131_072);
    expect(decoded.entryCount).toBe(MINIMUM_STATUS_LIST_ENTRIES);
    expect(decoded.statusSize).toBe(1); // §2.2: absent statusSize "MUST be processed as 1"
    expect(decoded.bits.every((b) => b === 0)).toBe(true);
    // §3.2 step 13: "If status is 0, set the valid key in result to true".
    expect(statusAt(decoded, 0)).toBe(0);
    expect(statusAt(decoded, 4242)).toBe(0);
    expect(statusAt(decoded, 131_071)).toBe(0);
  });

  it('is GZIP inside base64url inside multibase, in that order', () => {
    // §2.2: encodedList is "a Multibase-encoded base64url (with no padding) representation of the
    // GZIP-compressed bitstring", so peeling multibase then base64url must expose GZIP's magic.
    const gz = multibaseDecode(SPEC_EXAMPLE_ENCODED_LIST);
    expect(Buffer.from(gz.subarray(0, 3)).toString('hex')).toBe('1f8b08'); // RFC1952 ID1 ID2 CM
  });
});

describe('revoked / unrevoked lookups', () => {
  it('a revoked index reads set and an unrevoked one reads clear', async () => {
    const list = await handBuiltList('revocation', [42, 4242, 131_071]);
    const decoded = await decodeStatusList(list);
    for (const revoked of [42, 4242, 131_071]) {
      expect(statusAt(decoded, revoked)).toBe(1);
      expect(await isStatusSet(list, revoked)).toBe(true);
    }
    for (const live of [0, 41, 43, 4241, 4243, 131_070]) {
      expect(statusAt(decoded, live)).toBe(0);
      expect(await isStatusSet(list, live)).toBe(false);
    }
  });

  it('agrees with our own encoder (encoder and decoder share one bit order)', async () => {
    const mine = await encodeStatusList({ statusPurpose: 'revocation', set: [7, 8, 9] });
    const theirs = await handBuiltList('revocation', [7, 8, 9]);
    const a = await decodeStatusList(mine);
    const b = await decodeStatusList(theirs);
    expect(Buffer.from(a.bits).toString('hex')).toBe(Buffer.from(b.bits).toString('hex'));
  });

  it('raises RANGE_ERROR for an index past the end of the list — §3.2 step 10', async () => {
    const decoded = await decodeStatusList(await handBuiltList('revocation', []));
    expect(() => statusAt(decoded, MINIMUM_STATUS_LIST_ENTRIES)).toThrow(/RANGE_ERROR/);
    expect(() => statusAt(decoded, -1)).toThrow(StatusListError);
    expect(() => statusAt(decoded, 1.5)).toThrow(StatusListError);
    expect(statusAt(decoded, MINIMUM_STATUS_LIST_ENTRIES - 1)).toBe(0);
  });
});

describe('the 131,072-entry minimum is a REJECTION, not a padding rule', () => {
  it('rejects a list one entry short of the minimum', async () => {
    // §3.2 step 9: "If the length of the revocation bitstring divided by statusSize is less than
    // minimumNumberOfEntries, raise a STATUS_LIST_LENGTH_ERROR." step 2 fixes that at 131,072.
    const short = await handBuiltList('revocation', [], MINIMUM_STATUS_LIST_ENTRIES - 8);
    await expect(decodeStatusList(short)).rejects.toThrow(/STATUS_LIST_LENGTH_ERROR/);
    await expect(decodeStatusList(short)).rejects.toThrow(StatusListError);
  });

  it('rejects a tiny 100-entry list rather than padding it out', async () => {
    // A 100-entry list would make "the credential at index 42 of this list" nearly a name.
    const tiny = await handBuiltList('revocation', [42], 104);
    await expect(decodeStatusList(tiny)).rejects.toThrow(/STATUS_LIST_LENGTH_ERROR/);
    // ...and specifically NOT "index 42 is not revoked".
    await expect(isStatusSet(tiny, 42)).rejects.toThrow(StatusListError);
  });

  it('accepts exactly the minimum', async () => {
    const exact = await decodeStatusList(await handBuiltList('revocation', []));
    expect(exact.entryCount).toBe(MINIMUM_STATUS_LIST_ENTRIES);
  });

  it('applies the floor to ENTRIES, not bytes, when statusSize > 1', async () => {
    // §3.2 step 9 divides the bitstring length by statusSize before comparing. A 16 KB list at
    // statusSize 2 holds only 65,536 entries and is therefore too short.
    const twoBit = await handBuiltList('revocation', [], MINIMUM_STATUS_LIST_ENTRIES / 2, 2);
    await expect(decodeStatusList(twoBit)).rejects.toThrow(/STATUS_LIST_LENGTH_ERROR/);
    const wide = await handBuiltList('revocation', [3], MINIMUM_STATUS_LIST_ENTRIES, 2);
    const decoded = await decodeStatusList(wide);
    expect(decoded.entryCount).toBe(MINIMUM_STATUS_LIST_ENTRIES);
    expect(decoded.statusSize).toBe(2);
    expect(statusAt(decoded, 3)).not.toBe(0);
    expect(statusAt(decoded, 4)).toBe(0);
  });

  it('refuses to BUILD a list below the minimum either', async () => {
    await expect(
      encodeStatusList({ statusPurpose: 'revocation', entries: 1024 }),
    ).rejects.toThrow(StatusListError);
    await expect(
      encodeStatusList({ statusPurpose: 'revocation', set: [MINIMUM_STATUS_LIST_ENTRIES] }),
    ).rejects.toThrow(StatusListError);
  });
});

describe('statusPurpose', () => {
  it('accepts revocation and suspension', async () => {
    for (const purpose of ['revocation', 'suspension'] as const) {
      const decoded = await decodeStatusList(await handBuiltList(purpose, [1]));
      expect(decoded.statusPurpose).toBe(purpose);
      expect(statusAt(decoded, 1)).toBe(1);
    }
  });

  it('REJECTS an unrecognised purpose instead of reading it as "not revoked"', async () => {
    // §2.1 also defines "refresh" and "message". Neither answers "may I accept this credential",
    // and treating an unknown purpose as a pass is the exact silent failure being prevented.
    for (const purpose of ['message', 'refresh', 'REVOCATION', '', 'revocations']) {
      await expect(decodeStatusList(await handBuiltList(purpose, []))).rejects.toThrow(
        /unsupported statusPurpose/,
      );
    }
  });

  it('rejects a purpose mismatch — §3.2 step 5', async () => {
    const suspension = await handBuiltList('suspension', [9]);
    await expect(
      decodeStatusList(suspension, { expectedPurpose: 'revocation' }),
    ).rejects.toThrow(/statusPurpose mismatch/);
    await expect(
      decodeStatusList(suspension, { expectedPurpose: 'suspension' }),
    ).resolves.toBeDefined();
  });
});

describe('malformed input fails closed', () => {
  it('rejects a non-GZIP payload', async () => {
    const notGzip = `u${Buffer.from(new Uint8Array(64)).toString('base64url')}`;
    await expect(
      decodeStatusList({ statusPurpose: 'revocation', encodedList: notGzip }),
    ).rejects.toThrow(/not valid GZIP/);
  });

  it('rejects a truncated GZIP payload', async () => {
    const full = multibaseDecode(SPEC_EXAMPLE_ENCODED_LIST);
    const cut = `u${Buffer.from(full.subarray(0, full.length - 6)).toString('base64url')}`;
    await expect(
      decodeStatusList({ statusPurpose: 'revocation', encodedList: cut }),
    ).rejects.toThrow(StatusListError);
  });

  it('rejects a GZIP payload whose CRC has been corrupted', async () => {
    const full = Uint8Array.from(multibaseDecode(SPEC_EXAMPLE_ENCODED_LIST));
    full[full.length - 5] = (full[full.length - 5] as number) ^ 0xff;
    const bad = `u${Buffer.from(full).toString('base64url')}`;
    await expect(
      decodeStatusList({ statusPurpose: 'revocation', encodedList: bad }),
    ).rejects.toThrow(StatusListError);
  });

  it('rejects a decompression bomb rather than buffering it', async () => {
    const bomb = `u${Buffer.from(
      await gzipRaw(new Uint8Array(MAX_STATUS_LIST_BYTES + 1024)),
    ).toString('base64url')}`;
    await expect(
      decodeStatusList({ statusPurpose: 'revocation', encodedList: bomb }),
    ).rejects.toThrow(/ceiling/);
  });

  it('rejects a nonsense statusSize', async () => {
    const base = await handBuiltList('revocation', []);
    for (const statusSize of [0, -1, 1.5, 9, 64]) {
      await expect(decodeStatusList({ ...base, statusSize })).rejects.toThrow(StatusListError);
    }
  });

  it('rejects a non-object list', async () => {
    await expect(
      decodeStatusList(null as unknown as BitstringStatusList),
    ).rejects.toThrow(StatusListError);
  });
});

/* -------------------------------------------------------------------------- */
/* statusMessage is mandatory above one bit (§2.2)                             */
/* -------------------------------------------------------------------------- */

describe('statusMessage — §2.2, enforced', () => {
  /** A conforming statusMessage table of the right length for `size`. */
  const table = (size: number): Array<{ status: string; message: string }> =>
    Array.from({ length: 2 ** size }, (_, v) => ({
      status: `0x${v.toString(16)}`,
      message: v === 0 ? 'valid' : `code ${v}`,
    }));

  /** A conforming multi-bit list, minus its statusMessage. */
  async function twoBitList(): Promise<BitstringStatusList> {
    const withMessages = await handBuiltList(
      'revocation',
      [3],
      MINIMUM_STATUS_LIST_ENTRIES,
      2,
    );
    const { statusMessage: _drop, ...rest } = withMessages;
    return rest;
  }

  it('REJECTS a statusSize > 1 list that omits statusMessage', async () => {
    // "If statusSize is provided and is greater than 1, then the property
    //  credentialStatus.statusMessage MUST be present."
    const bare = await twoBitList();
    await expect(decodeStatusList(bare)).rejects.toThrow(StatusListError);
    await expect(decodeStatusList(bare)).rejects.toThrow(/statusMessage is REQUIRED/);
    // and the convenience door is shut too — never "index 3 is not revoked".
    await expect(isStatusSet(bare, 3)).rejects.toThrow(/statusMessage is REQUIRED/);
  });

  it('accepts the same list once statusMessage is present, and still reads the right bit', async () => {
    const ok = { ...(await twoBitList()), statusMessage: table(2) };
    const decoded = await decodeStatusList(ok);
    expect(decoded.statusSize).toBe(2);
    expect(decoded.entryCount).toBe(MINIMUM_STATUS_LIST_ENTRIES);
    expect(statusAt(decoded, 3)).not.toBe(0);
    expect(statusAt(decoded, 4)).toBe(0);
  });

  it('statusSize 1 may omit statusMessage — MAY, not MUST', async () => {
    const one = await handBuiltList('revocation', [7]);
    expect(one.statusMessage).toBeUndefined();
    expect((await decodeStatusList(one)).entryCount).toBe(MINIMUM_STATUS_LIST_ENTRIES);
  });

  it('validates the table whenever it is present, even at statusSize 1', async () => {
    // "statusMessage MAY be present if statusSize is 1" — but the length rule still applies.
    const one = await handBuiltList('revocation', []);
    await expect(
      decodeStatusList({ ...one, statusMessage: table(1) }),
    ).resolves.toMatchObject({ statusSize: 1 });
    await expect(
      decodeStatusList({ ...one, statusMessage: table(2) }),
    ).rejects.toThrow(/exactly 2 elements/);
  });

  it('demands exactly 2**statusSize elements, not merely "some"', async () => {
    const bare = await twoBitList();
    for (const size of [1, 3, 4]) {
      await expect(
        decodeStatusList({ ...bare, statusMessage: table(size) }),
      ).rejects.toThrow(/exactly 4 elements for statusSize 2/);
    }
  });

  it('rejects malformed statusMessage entries', async () => {
    const bare = await twoBitList();
    const bad: Array<[string, unknown]> = [
      ['not an array', { status: '0x0', message: 'valid' }],
      ['a string', 'valid'],
      ['null entries', [null, null, null, null]],
      ['missing status', [{ message: 'a' }, { message: 'b' }, { message: 'c' }, { message: 'd' }]],
      ['status without the 0x prefix', table(2).map((e, i) => (i === 0 ? { ...e, status: '0' } : e))],
      ['non-hex status', table(2).map((e, i) => (i === 1 ? { ...e, status: '0xzz' } : e))],
      ['numeric status', table(2).map((e, i) => (i === 2 ? { ...e, status: 2 } : e))],
      ['non-string message', table(2).map((e, i) => (i === 3 ? { ...e, message: 42 } : e))],
    ];
    for (const [label, statusMessage] of bad) {
      await expect(
        decodeStatusList({ ...bare, statusMessage } as unknown as BitstringStatusList),
        label,
      ).rejects.toThrow(StatusListError);
    }
  });

  it('encodeStatusList emits a conforming table above one bit, so it never builds what it refuses', async () => {
    const wide = await encodeStatusList({ statusPurpose: 'revocation', statusSize: 2, set: [9] });
    expect(wide.statusMessage).toHaveLength(4);
    expect(wide.statusMessage?.[0]).toEqual({ status: '0x0', message: 'valid' });
    // Round-trips through the decoder it is paired with — the encoder/decoder agreement this
    // module exists to keep.
    const decoded = await decodeStatusList(wide);
    expect(statusAt(decoded, 9)).not.toBe(0);
    expect(statusAt(decoded, 10)).toBe(0);

    // ...and a single-bit list still has no table, because the spec only says MAY there.
    const narrow = await encodeStatusList({ statusPurpose: 'revocation', set: [] });
    expect(narrow.statusMessage).toBeUndefined();
  });

  it('a missing statusMessage fails verification CLOSED, it does not read as "not revoked"', async () => {
    // The whole reason this is worth enforcing: every rejection path here must land on
    // status-list-invalid, never on a green light.
    const bare = await twoBitList();
    await expect(isStatusSet(bare, 0)).rejects.toThrow(StatusListError);
    await expect(isStatusSet(bare, 3)).rejects.toThrow(StatusListError);
  });
});
