import { Keypair, Networks, WebAuth } from '@stellar/stellar-sdk';
import { describe, expect, it } from 'vitest';

import { AnchorError, parseDeposit, parseQuote, verifyChallenge } from '../onboard/onramp.js';

const anchor = Keypair.random();
const client = Keypair.random();
const baseUrl = 'https://anchor.example';
const config = { signingKey: anchor.publicKey(), networkPassphrase: Networks.TESTNET, baseUrl };

function challenge(opts: { server?: Keypair; passphrase?: string; client?: string; domain?: string } = {}): string {
  return WebAuth.buildChallengeTx(
    opts.server ?? anchor,
    opts.client ?? client.publicKey(),
    opts.domain ?? 'anchor.example',
    300,
    opts.passphrase ?? Networks.TESTNET,
    'anchor.example',
  );
}

describe('SEP-10 challenge verification', () => {
  it('accepts a challenge signed by the anchor for this client on this network', () => {
    expect(() => verifyChallenge(challenge(), config, client.publicKey())).not.toThrow();
  });

  it('rejects a challenge signed by a different server key', () => {
    expect(() => verifyChallenge(challenge({ server: Keypair.random() }), config, client.publicKey())).toThrow();
  });

  it('rejects a challenge built for another network', () => {
    expect(() => verifyChallenge(challenge({ passphrase: Networks.PUBLIC }), config, client.publicKey())).toThrow();
  });

  it('rejects a challenge addressed to another client account', () => {
    const other = Keypair.random().publicKey();
    expect(() => verifyChallenge(challenge({ client: other }), config, client.publicKey())).toThrow(AnchorError);
  });

  it('rejects a challenge for another home domain', () => {
    expect(() => verifyChallenge(challenge({ domain: 'other.example' }), config, client.publicKey())).toThrow();
  });
});

describe('anchor response parsing', () => {
  it('reads a SEP-38 quote', () => {
    const q = parseQuote({
      id: 'qt_1',
      price: '49.0',
      total_price: '49.2',
      sell_amount: '500.00',
      buy_amount: '10.16',
      expires_at: '2030-01-01T00:00:00Z',
      sell_asset: 'iso4217:TRY',
    });
    expect(q).toEqual({ id: 'qt_1', price: '49.0', totalPrice: '49.2', sellAmount: '500.00', buyAmount: '10.16', expiresAt: '2030-01-01T00:00:00Z' });
  });

  it('refuses a quote without an id', () => {
    expect(() => parseQuote({ price: '1', total_price: '1', sell_amount: '1', buy_amount: '1', expires_at: 'x' })).toThrow(AnchorError);
  });

  it('reads SEP-6 deposit instructions in the SEP-9 object form', () => {
    const d = parseDeposit({
      id: 'sep_1',
      instructions: {
        bank_name: { value: 'TR Mock Bank', description: '' },
        bank_account_number: { value: 'TR05000990', description: '' },
        external_transfer_memo: { value: 'TRMA-1', description: '' },
      },
    });
    expect(d).toEqual({ id: 'sep_1', bankName: 'TR Mock Bank', iban: 'TR05000990', memo: 'TRMA-1' });
  });

  it('reads SEP-6 deposit instructions in the flat form', () => {
    const d = parseDeposit({ id: 'sep_2', bank_name: 'B', bank_account_number: 'TR1', external_transfer_memo: 'M' });
    expect(d).toEqual({ id: 'sep_2', bankName: 'B', iban: 'TR1', memo: 'M' });
  });
});
