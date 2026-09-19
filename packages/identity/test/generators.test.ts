/**
 * The generator set is a CROSS-LANGUAGE WIRE CONTRACT, in the same class as fixtures/vectors.json.
 * `contracts/kyc-gate/src/bbs.rs::create_generators` derives it on chain and this package derives
 * either suite says so. `.well-known/issuer` publishes what this file pins, so "looks plausible"
 * is not a standard that can be applied here.
 *
 * Three independent pins, deliberately not one:
 *
 *   1. Q_1 against `Q1_UNCOMPRESSED` READ OUT OF THE RUST SOURCE at test time — not copied, so a
 *      change on the Rust side turns this red rather than being mirrored by hand. This is the same
 *      technique `packages/gateway/test/chain/constants.test.ts` uses on `lib.rs`.
 *   2. All thirteen against frozen hex below, which `bbs_generators_match_the_typescript_export`
 *      in `contracts/kyc-gate/src/test.rs` asserts the CONTRACT produces. Pinning only Q_1 would
 *      leave the `I2OSP(i, 8)` loop index unpinned for i > 1 — the exact bit-exact wire detail
 *      `bbs.rs` warns about.
 *   3. Against `@digitalbazaar/bbs-signatures`' own `create_generators`, the library that signed
 *      `fixtures/vectors.json`, imported by FILE PATH because its `exports` map has no subpath.
 *      That one is skipped rather than failed if the path moves: it is corroboration, and pins
 *      1 and 2 are the contract.
 */

import { existsSync, readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import {
  BBS_API_ID,
  BBS_GENERATOR_COUNT,
  GeneratorError,
  SCHEMA_ATTRIBUTE_COUNT,
  bbsGenerators,
  createGenerators,
  toHex,
} from '../src/index.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = join(HERE, '..', '..', '..');
const BBS_RS = join(REPO, 'contracts', 'kyc-gate', 'src', 'bbs.rs');
const TEST_RS = join(REPO, 'contracts', 'kyc-gate', 'src', 'test.rs');

/**
 * The thirteen generators, uncompressed `be(X) ‖ be(Y)`. FROZEN. Changing one of these lines
 * means every credential ever signed under schema v1 is void; there is no migration.
 */
const FROZEN_UNCOMPRESSED: readonly string[] = [
  '09ec65b70a7fbe40c874c9eb041c2cb0a7af36ccec1bea48fa2ba4c2eb67ef7f9ecb17ed27d38d27cdeddff44c8137be0e251c6621fa1d69fc1f471b9753a5a6e0772dc3af4b8d793a544548052fe03f75a76ae208d96556fcf542fdece6fda7',
  '18cd5313283aaf5db1b3ba8611fe6070d19e605de4078c38df36019fbaad0bd28dd090fd24ed27f7f4d22d5ff5dea7d40a9d63cda350d1a810eccc89c509274231c3e6ee9d471a8b924a71b170035e166a8db9a4ba39d04e0ca2b33a47b73c08',
  '031fbe20c5c135bcaa8d9fc4e4ac665cc6db0226f35e737507e803044093f37697a9d452490a970eea6f9ad6c3dcaa3a18c1678525a53bf03d9728cf252cdac04eb5d94bad3876e102de933014a387003da21ec158a4a89f9b0f34d6533cb384',
  '1479263445f4d2108965a9086f9d1fdc8cde77d14a91c856769521ad3344754cc5ce90d9bc4c696dffbc9ef1d6ad1b621901c15e64733b12e043edcb8e1938a6c757ac57bf2ae98777eb14d5633adc15160659534bbfd3a125ef73c7a71195de',
  '0c0401766d2128d4791d922557c7b4d1ae9a9b508ce266575244a8d6f32110d7b0b7557b77604869633bb49afbe200350f1a8bbefe73d4c40e54fd64fc716e9194accd0a60b31b2eaec0e3db1431aafcee3167069881517f4110abe773456e88',
  '195d2898370ebc542857746a316ce32fa5151c31f9b57915e308ee9d1de7db69127d919e984ea0747f5223821b5963350d450e64c34ee92a685e504a588fdf01fccff32ad34871860e3b9a9c7c9e15e8c5d8af28b3da37980cbd8e07d820454b',
  '0f19359ae6ee508157492c06765b7df09e2e5ad591115742f2de9c08572bb2845cbf03fd7e23b7f031ed9c7564e52f3902af3ec6aa5643ab7369ac81cb1bcbd71777dbfb7ae7842df6450b55940ed88ba15b1b810323985c005f5a4ecae9342e',
  '0bc914abe2926324b2c848e8a411a2b6df18cbe7758db8644145fefb0bf0a2d558a8c9946bd35e00c69d167aadf304c11315c0a9c22a3b42aba7b868808d5ad7f9b899bd87388a58f6b7e11ae686dc52969f732d3d257f0b769161075beb7950',
  '00755b3eb0dd4249cbefd20f177cee88e0761c066b71794825c9997b551f24051c352567ba6c01e57ac75dff763eaa17080f07fa454c89bbe9f4a4b141cf62c37b0a7ddc1d6c00a75a2415aedaf2581dac41ce6336b3f229a49ca55b95083fba',
  '02701eb98070728e1769525e73abff1783cedc364adb20c05c897a62f2ab2927f86f118dcb7819a7b218d8f3fee4bd7f016b44294c9c63516304b43c466469ec4f1d3e1b8953102fb4940570ec167369f6d937874e877f8c56fb35d8f1ca5e76',
  '01f229540474f4d6f1134761b92b788128c7ac8dc9b0c52d59493132679673032ac7db3fb3d79b46b13c1c41ee495bca186b31df3cfd967dab35da581652ac72e7ea7ded0cd1f14ce977604e30019d6f56a2d513641f9a71cbf625ca4268cd0b',
  '089b76d1df62140633f1635c8b82a273308bf801f64e3e12bad0c9b48e62a626aeb08a7ffb30211be340f1d92d94b0c2052e5bec6c160b007249ee9ecbd3d2dd3a900b9936b7c234d4f314d4cd60fc96256a60c22156cfe16775046601827042',
  '065f53f44d8ab28ff0848061d84944ee897e9041c9d9e2a990312ba8c08f171fdab0d6748703bc7b4870595a12d9f01f11fbdef742062d66b1c757668bde67d1df3ec5df42159393da9d5a880f3196b80c20a19b52158d02397c6739283df79b',
];

/** `sha256` over the thirteen uncompressed encodings concatenated, 1,248 bytes in. */
const FROZEN_ROOT = 'a8b625391c8a4bdeb3d1840f4851da6c362559e98d25ab69c51a9732f242b48d';

/** Pull a `concat!("…", "…")` Rust string constant out of a source file, hex joined. */
function rustConcatConst(source: string, name: string): string {
  const start = source.indexOf(`const ${name}`);
  if (start < 0) throw new Error(`${name} is gone from the Rust source — the pin cannot run`);
  const end = source.indexOf(';', start);
  const body = source.slice(start, end);
  const parts = [...body.matchAll(/"([0-9a-f]+)"/g)].map((m) => m[1] as string);
  if (parts.length === 0) throw new Error(`${name} has no hex literal`);
  return parts.join('');
}

describe('BBS+ generators are derived, and identical to the on-chain derivation', () => {
  it('derives L+1 = 13 points for the frozen 12-attribute schema', () => {
    const g = bbsGenerators();
    expect(BBS_GENERATOR_COUNT).toBe(SCHEMA_ATTRIBUTE_COUNT + 1);
    expect(BBS_GENERATOR_COUNT).toBe(13);
    expect(g.count).toBe(13);
    expect(g.uncompressed).toHaveLength(13);
    expect(g.compressed).toHaveLength(13);
    for (const u of g.uncompressed) expect(u).toHaveLength(96 * 2);
    for (const c of g.compressed) expect(c).toHaveLength(48 * 2);
  });

  it('matches the FROZEN thirteen, which the Rust suite asserts the contract produces', () => {
    expect([...bbsGenerators().uncompressed]).toEqual([...FROZEN_UNCOMPRESSED]);
  });

  it('PIN 1 — Q_1 equals the constant read out of contracts/kyc-gate/src/test.rs', () => {
    const q1 = rustConcatConst(readFileSync(TEST_RS, 'utf8'), 'Q1_UNCOMPRESSED');
    expect(q1).toHaveLength(96 * 2);
    expect(bbsGenerators().uncompressed[0]).toBe(q1);
  });

  it('PIN 1b — the domain-separation constants match bbs.rs byte for byte', () => {
    const rs = readFileSync(BBS_RS, 'utf8');
    // The Rust constants are byte-string literals; check the exact strings appear.
    expect(rs).toContain(`b"${BBS_API_ID}"`);
    expect(rs).toContain(`b"${BBS_API_ID}MESSAGE_GENERATOR_SEED"`);
    expect(rs).toContain(`b"${BBS_API_ID}SIG_GENERATOR_SEED_"`);
    expect(rs).toContain(`b"${BBS_API_ID}SIG_GENERATOR_DST_"`);
    // ...and that the count the contract derives is ours.
    expect(rs).toContain(`const SCHEMA_MESSAGE_COUNT: u32 = ${SCHEMA_ATTRIBUTE_COUNT};`);
  });

  it('PIN 2 — the frozen thirteen are also pinned on the Rust side', () => {
    // If the Rust test that owns the other half of this contract is deleted or renamed, this
    // file is pinning one side of a two-sided agreement and does not know it.
    const rs = readFileSync(TEST_RS, 'utf8');
    expect(rs).toContain('fn bbs_generators_match_the_typescript_export()');
    // Every frozen value must literally appear in the Rust pin, and so must the root.
    for (const g of FROZEN_UNCOMPRESSED) {
      for (let i = 0; i < g.length; i += 64) expect(rs).toContain(g.slice(i, i + 64));
    }
    expect(rs).toContain(FROZEN_ROOT.slice(0, 64));
  });

  it('PIN 3 — matches @digitalbazaar/bbs-signatures, the library that signed the vectors', async () => {
    const util = join(REPO, 'node_modules', '@digitalbazaar', 'bbs-signatures', 'lib', 'bbs', 'util.js');
    const suites = join(REPO, 'node_modules', '@digitalbazaar', 'bbs-signatures', 'lib', 'bbs', 'ciphersuites.js');
    if (!existsSync(util) || !existsSync(suites)) {
      // Corroboration only. Pins 1 and 2 are the contract; do not turn a hoisting change into a
      // failure that looks like a cryptographic one.
      expect(true).toBe(true);
      return;
    }
    const { create_generators, createApiId } = (await import(util)) as {
      create_generators: (o: unknown) => Array<{ toBytes: (c: boolean) => Uint8Array }>;
      createApiId: (id: string, suffix: string) => Uint8Array;
    };
    const { CIPHERSUITES } = (await import(suites)) as {
      CIPHERSUITES: Record<string, { ciphersuite_id: string }>;
    };
    const cs = CIPHERSUITES.BLS12381_SHA256 as { ciphersuite_id: string };
    const api_id = createApiId(cs.ciphersuite_id, 'H2G_HM2S_');
    expect(new TextDecoder().decode(api_id)).toBe(BBS_API_ID);
    const ref = create_generators({ count: BBS_GENERATOR_COUNT, api_id, ciphersuite: cs });
    expect(ref.map((p) => toHex(p.toBytes(false)))).toEqual([...FROZEN_UNCOMPRESSED]);
  });

  it('generators_root is sha256 over the concatenated UNCOMPRESSED encodings', () => {
    const blob = Buffer.concat(FROZEN_UNCOMPRESSED.map((h) => Buffer.from(h, 'hex')));
    expect(blob.length).toBe(13 * 96);
    expect(blob.length).toBe(1_248);
    expect(createHash('sha256').update(blob).digest('hex')).toBe(FROZEN_ROOT);
    expect(bbsGenerators().root).toBe(FROZEN_ROOT);

    // rejected alternatives are pinned by VALUE, not just asserted to differ, because the
    // failure mode is silent: all three are 32 bytes that describe nothing about themselves,
    // so a relying party that guesses wrong sees a mismatch and cannot tell which encoding it
    // guessed. `bbs.rs::calculate_domain` builds the second of these on every `attest_bbs`,
    // which makes it the reading a kyc-registry author is most likely to reach for.
    const compressed = Buffer.concat(
      bbsGenerators().compressed.map((h) => Buffer.from(h, 'hex')),
    );
    expect(compressed.length).toBe(13 * 48);
    expect(createHash('sha256').update(compressed).digest('hex')).toBe(
      'bd40396e37860601a72ebed0b9351a86c99ead181b10605f19afa4f94f2a6d8c',
    );
    // `dom_octs` = I2OSP(L, 8) ‖ 13 compressed, i.e. the BBS `serialize()` form, L = 12 to match
    // `SCHEMA_MESSAGE_COUNT`.
    const lenPrefix = Buffer.alloc(8);
    lenPrefix.writeBigUInt64BE(BigInt(BBS_GENERATOR_COUNT - 1));
    expect(
      createHash('sha256').update(Buffer.concat([lenPrefix, compressed])).digest('hex'),
    ).toBe('524451dfde46907f1445c3a22359578426f1762a02e15edec879d130250199c0');
    expect(createHash('sha256').update(compressed).digest('hex')).not.toBe(FROZEN_ROOT);
  });

  it('compressed and uncompressed describe the same thirteen points', () => {
    const g = bbsGenerators();
    for (let i = 0; i < g.count; i++) {
      const c = g.compressed[i] as string;
      const u = g.uncompressed[i] as string;
      // The compressed form is x with the compression bit set, so it shares x with the
      // uncompressed form once the top three flag bits are masked off.
      const cx = Buffer.from(c, 'hex');
      const ux = Buffer.from(u.slice(0, 96), 'hex');
      expect(cx[0]! & 0x1f).toBe(ux[0]! & 0x1f);
      expect(cx.subarray(1).toString('hex')).toBe(ux.subarray(1).toString('hex'));
      expect(cx[0]! & 0x80).toBe(0x80);
    }
  });

  it('is memoised, deterministic and refuses a nonsense count', () => {
    expect(bbsGenerators()).toBe(bbsGenerators());
    expect(createGenerators(3).map(toHex)).toEqual([...FROZEN_UNCOMPRESSED].slice(0, 3));
    for (const bad of [0, -1, 1.5, Number.NaN]) {
      expect(() => createGenerators(bad)).toThrow(GeneratorError);
    }
  });

  it('the memoised set is FROZEN, so nothing in-process can poison the published document', () => {
    // Memoisation makes this process-global state and `readonly` is erased at runtime, so before
    // the freeze a single stray assignment anywhere in the process permanently changed what
    const g = bbsGenerators();
    expect(Object.isFrozen(g)).toBe(true);
    expect(Object.isFrozen(g.uncompressed)).toBe(true);
    expect(Object.isFrozen(g.compressed)).toBe(true);
    // ESM is always strict mode, so the write throws rather than failing silently.
    expect(() => {
      (g.uncompressed as string[])[0] = 'poisoned';
    }).toThrow(TypeError);
    expect(() => {
      (g as { root: string }).root = 'poisoned';
    }).toThrow(TypeError);
    expect(bbsGenerators().uncompressed[0]).toBe(FROZEN_UNCOMPRESSED[0]);
    expect(bbsGenerators().root).toBe(FROZEN_ROOT);

    // `createGenerators` still hands out a fresh mutable array — it is a derivation, not the
    // shared cache, and a caller is entitled to consume the bytes.
    expect(Object.isFrozen(createGenerators(1))).toBe(false);
  });
});
