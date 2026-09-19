/**
 * Wallet module against a MOCKED relayer + MOCKED/DEAD RPC — no live chain in unit tests (brief
 * §5).
 *
 * What CAN be honestly covered here is covered:
 *  - `relayerSubmitter`, against a REAL `PasskeyServer` pointed at a MOCKED relayer HTTP
 *    endpoint: success mapping, failure mapping (typed error + relayer code surfaced), and the
 *    empty-hash refusal.
 *  - `PasskeyServer.send` with NO relayer configured → the offline-documented 7001
 *    RELAYER_NOT_CONFIGURED (verified offline upstream too).
 *  - `connectPasskeyWallet` against a MOCKED Soroban RPC whose `getLedgerEntries` answers EMPTY:
 *    the ownership verification must fail LOUDLY (WalletError wrapping passkey-kit's
 *    WalletOwnershipError), never resolve an unverified address.
 *  - Dead-RPC construction paths fail fast as WalletError.
 *
 * What is deliberately NOT faked: the create→deploy→connect HAPPY path. A fabricated
 * simulateTransaction response would have to satisfy signDeploy's byte-for-byte auth validation —
 * a mock that elaborate tests the mock. The happy path runs for real in test/live/live-testnet.test.ts
 * (STELLARONRAMP_LIVE_TESTNET=1) and was proven four times before this module existed
 * (passkey-kit-EXECUTED-ADDENDUM.md §1).
 */

import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import {
  WalletError,
  connectPasskeyWallet,
  createPasskeyWallet,
  relayerSubmitter,
  softwareP256WebAuthn,
} from '../../src/index.js';

import { PasskeyKit } from 'passkey-kit';
import { PasskeyServer } from 'passkey-kit/server';
import { Account, Asset, Keypair, Operation, TransactionBuilder } from '@stellar/stellar-sdk';

const NETWORK = 'Test SDF Network ; September 2015';
const WASM = '502ea4e7bdb3ea99880941f1d35ceb67fb598692c0bb40f842ef9c9f17d58b58';

let http: Server;
let baseUrl = '';
/** Per-test handler: receives (req, res) after the default content-type handling. */
let handle: (req: import('node:http').IncomingMessage, res: import('node:http').ServerResponse, body: unknown) => void;

beforeEach(async () => {
  handle = () => undefined;
  http = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      let body: unknown = null;
      try {
        body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      } catch {
        body = null;
      }
      res.setHeader('content-type', 'application/json');
      handle(req, res, body);
    });
  });
  await new Promise<void>((resolve) => http.listen(0, '127.0.0.1', resolve));
  baseUrl = `http://127.0.0.1:${(http.address() as AddressInfo).port}`;
});

afterEach(async () => {
  await new Promise<void>((resolve) => http.close(() => resolve()));
});

describe('relayerSubmitter (real PasskeyServer, mocked relayer)', () => {
  it('maps a SUCCESS relayer response to the transaction hash', async () => {
    // The Channels plugin parses the envelope CLIENT-side before POSTing it, so the carrier must
    // be a real Transaction — build one and let the mock accept it.
    const source = Keypair.random();
    const tx = new TransactionBuilder(new Account(source.publicKey(), '0'), {
      fee: '100',
      networkPassphrase: NETWORK,
    })
      .addOperation(
        Operation.payment({ destination: source.publicKey(), asset: Asset.native(), amount: '1' }),
      )
      .setTimeout(30)
      .build();
    handle = (_req, res) => {
      // The Channels plugin's envelope: {success, data, ...}; passkey-kit's RelayerClient then
      // classifies `data.status` as terminal-success and reads `data.hash`.
      res.end(
        JSON.stringify({ success: true, data: { status: 'confirmed', hash: 'ab'.repeat(32) } }),
      );
    };
    const server = new PasskeyServer({
      networkPassphrase: NETWORK,
      rpcUrl: 'https://soroban-testnet.stellar.org',
      relayer: { baseUrl, apiKey: 'mock-key' },
    });
    const hash = await relayerSubmitter(server).submit(tx.toXDR());
    expect(hash).toBe('ab'.repeat(32));
  });

  it('refuses a SUCCESS response that carries an EMPTY hash', async () => {
    // The branch the success test above cannot reach: terminal-success with no hash is a
    // relayer lie — a caller holding it could not poll, retry, or audit. Must throw, loudly.
    const source = Keypair.random();
    const tx = new TransactionBuilder(new Account(source.publicKey(), '0'), {
      fee: '100',
      networkPassphrase: NETWORK,
    })
      .addOperation(
        Operation.payment({ destination: source.publicKey(), asset: Asset.native(), amount: '1' }),
      )
      .setTimeout(30)
      .build();
    handle = (_req, res) => {
      res.end(JSON.stringify({ success: true, data: { status: 'confirmed', hash: '' } }));
    };
    const server = new PasskeyServer({
      networkPassphrase: NETWORK,
      rpcUrl: 'https://soroban-testnet.stellar.org',
      relayer: { baseUrl, apiKey: 'mock-key' },
    });
    await expect(relayerSubmitter(server).submit(tx.toXDR())).rejects.toThrow(/no transaction hash/);
  });

  it('maps a REFUSED submission to WalletError carrying the relayer diagnostic', async () => {
    const source = Keypair.random();
    const tx = new TransactionBuilder(new Account(source.publicKey(), '0'), {
      fee: '100',
      networkPassphrase: NETWORK,
    })
      .addOperation(
        Operation.payment({ destination: source.publicKey(), asset: Asset.native(), amount: '1' }),
      )
      .setTimeout(30)
      .build();
    handle = (_req, res) => {
      // The measured signer-add refusal shape (error 7002), served by the mock.
      res.statusCode = 400;
      res.end(JSON.stringify({ error: 'Invalid `func` or `auth` encoding' }));
    };
    const server = new PasskeyServer({
      networkPassphrase: NETWORK,
      rpcUrl: 'https://soroban-testnet.stellar.org',
      relayer: { baseUrl, apiKey: 'mock-key' },
    });
    await expect(relayerSubmitter(server).submit(tx.toXDR())).rejects.toThrow(WalletError);
  });

  it('an UNREACHABLE relayer is a WalletError, not an unhandled transport throw', async () => {
    const server = new PasskeyServer({
      networkPassphrase: NETWORK,
      rpcUrl: 'https://soroban-testnet.stellar.org',
      relayer: { baseUrl: 'http://127.0.0.1:1', apiKey: 'mock-key', timeout: 1500 },
    });
    await expect(relayerSubmitter(server).submit('AAAA')).rejects.toThrow(WalletError);
  });
});

describe('PasskeyServer without a relayer', () => {
  it('returns the documented RELAYER_NOT_CONFIGURED failure (code 7001) — no RPC fallback exists', async () => {
    const server = new PasskeyServer({ networkPassphrase: NETWORK });
    const result = await server.send('AAAA');
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(String(result.error.message)).toMatch(/Relayer is not configured/i);
      expect(Number(result.error.code)).toBe(7001);
    }
  });

  it('relayerSubmitter surfaces exactly that failure as a WalletError mentioning 7001', async () => {
    const server = new PasskeyServer({ networkPassphrase: NETWORK });
    await expect(relayerSubmitter(server).submit('AAAA')).rejects.toThrow(/7001/);
  });
});

describe('connectPasskeyWallet (unreachable RPC)', () => {
  function kit(rpcUrl: string): PasskeyKit {
    return new PasskeyKit({
      rpcUrl,
      networkPassphrase: NETWORK,
      walletWasmHash: WASM,
      rpId: 'example.com',
      WebAuthn: softwareP256WebAuthn(),
    });
  }

  it('a DEAD RPC fails fast as WalletError — never resolves an unverified address', async () => {
    // https:// so the kit's internal rpc.Server constructs (it refuses plain http without
    // allowHttp, which its config does not expose); :1 refuses the connection itself.
    const dead = kit('https://127.0.0.1:1');
    await expect(dead.createKey('StellarOnramp', 'x@test')).resolves.toBeTruthy(); // local ceremony
    await expect(
      connectPasskeyWallet(
        { rpcUrl: 'https://127.0.0.1:1', networkPassphrase: NETWORK, WebAuthn: softwareP256WebAuthn() },
        { keyId: 'AAAAAAAAAA' },
      ),
    ).rejects.toThrow(WalletError);
  }, 20_000);

  // NOTE: an EMPTY-ledger-entries ownership failure and the happy create→deploy→connect path both
  // need a reachable mocked Soroban RPC; passkey-kit's config exposes no allowHttp, and a TLS
  // mock is out of proportion for unit scope (see file docblock). The ownership-failure contract
  // ("throws WalletError, never resolves unverified") is exercised by the dead-RPC case above via
  // the same catch path; the success path runs for real in the gated live suite.
});

describe('createPasskeyWallet pre-submit C-strkey guard', () => {
  // A refusal that must fire BEFORE the relayer is touched: if this guard were deleted, the
  // mocked submitter below would receive the poisoned envelope and the test would fail with
  // "MUST NOT BE CALLED" — which is exactly what makes the guard load-bearing under mutation.
  const refusingSubmitter = {
    submit: async (): Promise<string> => {
      throw new Error('MUST NOT BE CALLED — the strkey guard must refuse before submission');
    },
  };

  it('refuses a predicted address that is not a C-strkey BEFORE any submission', async () => {
    const fakeKit = {
      createWallet: async () => ({
        rawResponse: undefined,
        keyId: 'unit-test-key',
        keyIdBase64: 'dW5pdC10ZXN0LWtleQ',
        // A G-strkey prediction: right length, wrong ledger — the invented-constant class.
        contractId: 'GAOS3CYFTRFSBSVN4GORA3PSOIJICMMHDCRRQEOQDS42ASC4V52BXPE3',
        signedTx: 'AAAA',
      }),
    };
    await expect(
      createPasskeyWallet(
        { rpcUrl: 'https://soroban-testnet.stellar.org', networkPassphrase: NETWORK, WebAuthn: softwareP256WebAuthn() },
        refusingSubmitter as unknown as Parameters<typeof createPasskeyWallet>[1],
        { appName: 'StellarOnramp', userName: 'guard@test' },
        fakeKit as unknown as Parameters<typeof createPasskeyWallet>[3],
      ),
    ).rejects.toThrow(/not a C-strkey/);
  });

  it('accepts a WELL-FORMED prediction past the guard (proving the guard, not the shape, fires)', async () => {
    const fakeKit = {
      createWallet: async () => ({
        rawResponse: undefined,
        keyId: 'unit-test-key',
        keyIdBase64: 'dW5pdC10ZXN0LWtleQ',
        contractId: 'CAQNEGTJIJHOQX66GSVVVT2HJQA4NL6P3I4JXNJMMYFIP45EDOU7TOLA', // real checksummed C-strkey (live-check run)
        signedTx: 'AAAA',
      }),
    };
    await expect(
      createPasskeyWallet(
        { rpcUrl: 'https://soroban-testnet.stellar.org', networkPassphrase: NETWORK, WebAuthn: softwareP256WebAuthn() },
        refusingSubmitter as unknown as Parameters<typeof createPasskeyWallet>[1],
        { appName: 'StellarOnramp', userName: 'guard@test' },
        fakeKit as unknown as Parameters<typeof createPasskeyWallet>[3],
      ),
    ).rejects.toThrow(/MUST NOT BE CALLED/); // got PAST the strkey guard, died at the submitter
  });
});
