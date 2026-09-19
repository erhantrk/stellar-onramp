/**
 * The TRY → USDC on-ramp: the verified wallet's holder buys USDC through a SEP-compliant anchor.
 *
 * The kyc-gate contract decides WHO may buy (`check(wallet, OVER_18)` must read true); the anchor
 * sells them USDC for TRY. The anchor is the TR mock anchor the ecosystem provides for testnet
 * (`https://tr-mock-anchor.fly.dev`): SEP-1 discovery, SEP-10 authentication, SEP-12 customer
 * handoff, SEP-38 firm quotes and SEP-6 bank-account deposits, paying real testnet USDC.
 *
 * THE FUNDING ACCOUNT. SEP-10 authenticates a classic Stellar account by signature, and a passkey
 * smart wallet is a contract that cannot sign a SEP-10 challenge. So each portal account gets a
 * classic funding account (`G…`): a keypair generated here, funded by friendbot, with a USDC
 * trustline. The USDC lands there. THE DEMO SERVER HOLDS THAT SECRET (in `funding-keys.json` under
 * the data directory, mode 0600) — a production wallet signs SEP-10 with the person's own key and
 * this file does not exist. The passkey wallet stays the KYC subject; the funding account is the
 * cash account next to it.
 *
 * Nothing from the KYC wizard reaches the anchor. SEP-12 receives the minimal customer object the
 * anchor asks for; the documents, the date of birth and the document number never leave this
 * server's memory during the KYC run, and this module never sees them at all.
 */

import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';

import { Asset, Horizon, Keypair, Networks, Operation, TransactionBuilder, WebAuth } from '@stellar/stellar-sdk';

import type { DemoStep, EmitStep } from '../demo/demo-flow.js';

/* -------------------------------------------------------------------------- */
/* configuration                                                               */
/* -------------------------------------------------------------------------- */

export interface AnchorConfig {
  /** `https://tr-mock-anchor.fly.dev` */
  readonly baseUrl: string;
  /** The anchor's SIGNING_KEY from its stellar.toml; the SEP-10 challenge must be signed by it. */
  readonly signingKey: string;
  readonly networkPassphrase: string;
  readonly horizonUrl: string;
  readonly usdcIssuer: string;
  readonly explorerBase: string;
}

export const TR_MOCK_ANCHOR: AnchorConfig = {
  baseUrl: 'https://tr-mock-anchor.fly.dev',
  signingKey: 'GDXYO6FJCNXZEWGXD54GT76FGFYLOLSOGSOJLNQ6WGHCGEQPO7NTE73M',
  networkPassphrase: Networks.TESTNET,
  horizonUrl: 'https://horizon-testnet.stellar.org',
  usdcIssuer: 'GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5',
  explorerBase: 'https://stellar.expert/explorer/testnet',
};

export const ONRAMP_MIN_TRY = 50;
export const ONRAMP_MAX_TRY = 5000;

const FETCH_TIMEOUT_MS = 20_000;

/* -------------------------------------------------------------------------- */
/* funding-key custody                                                         */
/* -------------------------------------------------------------------------- */

interface FundingKeysFile {
  version: 1;
  /** account id → secret seed (S…). */
  keys: Record<string, string>;
}

/** Secrets of the per-account funding accounts. Dev-grade custody; see the module comment. */
export class JsonFileFundingKeyStore {
  readonly #path: string;
  readonly #keys = new Map<string, string>();

  constructor(path: string) {
    this.#path = path;
    if (!existsSync(path)) return;
    const raw = JSON.parse(readFileSync(path, 'utf8')) as Partial<FundingKeysFile>;
    if (raw.version !== 1 || typeof raw.keys !== 'object' || raw.keys === null) {
      throw new Error(`${path} is not a version-1 funding-keys file`);
    }
    for (const [id, secret] of Object.entries(raw.keys)) this.#keys.set(id, secret);
  }

  get(accountId: string): Keypair | undefined {
    const secret = this.#keys.get(accountId);
    return secret === undefined ? undefined : Keypair.fromSecret(secret);
  }

  /** Returns the existing keypair, or generates and persists one. */
  getOrCreate(accountId: string): Keypair {
    const existing = this.get(accountId);
    if (existing !== undefined) return existing;
    const kp = Keypair.random();
    this.#keys.set(accountId, kp.secret());
    const file: FundingKeysFile = { version: 1, keys: Object.fromEntries(this.#keys) };
    mkdirSync(dirname(this.#path), { recursive: true });
    const tmp = `${this.#path}.${process.pid}.tmp`;
    writeFileSync(tmp, JSON.stringify(file), { mode: 0o600 });
    renameSync(tmp, this.#path);
    return kp;
  }
}

/* -------------------------------------------------------------------------- */
/* anchor client                                                               */
/* -------------------------------------------------------------------------- */

export class AnchorError extends Error {
  override readonly name = 'AnchorError';
}

async function getJson(url: string, token?: string): Promise<Record<string, unknown>> {
  const res = await fetch(url, {
    headers: token === undefined ? {} : { authorization: `Bearer ${token}` },
    signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
  });
  const body = (await res.json().catch(() => null)) as Record<string, unknown> | null;
  if (!res.ok || body === null) {
    throw new AnchorError(`${new URL(url).pathname}: HTTP ${res.status} ${JSON.stringify(body).slice(0, 200)}`);
  }
  return body;
}

async function postJson(url: string, payload: unknown, token?: string): Promise<Record<string, unknown>> {
  const res = await fetch(url, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      ...(token === undefined ? {} : { authorization: `Bearer ${token}` }),
    },
    body: JSON.stringify(payload),
    signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
  });
  const body = (await res.json().catch(() => null)) as Record<string, unknown> | null;
  if (!res.ok || body === null) {
    throw new AnchorError(`${new URL(url).pathname}: HTTP ${res.status} ${JSON.stringify(body).slice(0, 200)}`);
  }
  return body;
}

function str(bag: Record<string, unknown>, key: string): string {
  const v = bag[key];
  if (typeof v !== 'string' || v.length === 0) throw new AnchorError(`anchor response has no "${key}"`);
  return v;
}

/**
 * SEP-10: fetch the challenge, verify it is the anchor's (signed by SIGNING_KEY, for this network,
 * for this client account), sign it, exchange it for a JWT. Exported separately so the verification
 * rules are unit-testable without the network.
 */
export function verifyChallenge(
  xdr: string,
  config: Pick<AnchorConfig, 'signingKey' | 'networkPassphrase' | 'baseUrl'>,
  clientAccount: string,
): void {
  const homeDomain = new URL(config.baseUrl).host;
  const { clientAccountID } = WebAuth.readChallengeTx(
    xdr,
    config.signingKey,
    config.networkPassphrase,
    homeDomain,
    homeDomain,
  );
  if (clientAccountID !== clientAccount) {
    throw new AnchorError(`SEP-10 challenge is for ${clientAccountID}, not ${clientAccount}`);
  }
}

export async function sep10Authenticate(config: AnchorConfig, kp: Keypair): Promise<string> {
  const challenge = await getJson(`${config.baseUrl}/auth?account=${kp.publicKey()}`);
  const xdr = str(challenge, 'transaction');
  verifyChallenge(xdr, config, kp.publicKey());
  const tx = TransactionBuilder.fromXDR(xdr, config.networkPassphrase);
  tx.sign(kp);
  const answer = await postJson(`${config.baseUrl}/auth`, { transaction: tx.toXDR() });
  return str(answer, 'token');
}

export interface Quote {
  id: string;
  price: string;
  totalPrice: string;
  sellAmount: string;
  buyAmount: string;
  expiresAt: string;
}

export function parseQuote(body: Record<string, unknown>): Quote {
  return {
    id: str(body, 'id'),
    price: str(body, 'price'),
    totalPrice: str(body, 'total_price'),
    sellAmount: str(body, 'sell_amount'),
    buyAmount: str(body, 'buy_amount'),
    expiresAt: str(body, 'expires_at'),
  };
}

export interface DepositInstructions {
  id: string;
  bankName: string;
  iban: string;
  memo: string;
}

export function parseDeposit(body: Record<string, unknown>): DepositInstructions {
  const id = str(body, 'id');
  const instructions = (body['instructions'] ?? {}) as Record<string, unknown>;
  const field = (k: string): string => {
    const v = instructions[k];
    if (v !== null && typeof v === 'object' && typeof (v as { value?: unknown }).value === 'string') {
      return (v as { value: string }).value;
    }
    return typeof v === 'string' ? v : '';
  };
  return {
    id,
    bankName: field('bank_name') || str(body, 'bank_name'),
    iban: field('bank_account_number') || (typeof body['bank_account_number'] === 'string' ? (body['bank_account_number'] as string) : ''),
    memo: field('external_transfer_memo') || (typeof body['external_transfer_memo'] === 'string' ? (body['external_transfer_memo'] as string) : ''),
  };
}

/* -------------------------------------------------------------------------- */
/* the flow                                                                    */
/* -------------------------------------------------------------------------- */

export interface OnrampResult {
  fundingAccount: string;
  tryAmount: string;
  usdcAmount: string;
  quoteId: string;
  depositId: string;
  stellarTxHash: string;
  usdcBalance: string;
}

export interface OnrampDeps {
  readonly anchor: AnchorConfig;
  readonly fundingKeys: JsonFileFundingKeyStore;
  /** `kyc-gate.check(wallet, OVER_18)` as the chain answers it. */
  readonly gateAllows: (walletCAddr: string) => Promise<boolean>;
}

const usdcAsset = (c: AnchorConfig): Asset => new Asset('USDC', c.usdcIssuer);

async function usdcBalance(c: AnchorConfig, account: string): Promise<string> {
  const server = new Horizon.Server(c.horizonUrl);
  const acc = await server.loadAccount(account);
  const line = acc.balances.find(
    (b) => b.asset_type !== 'native' && 'asset_code' in b && b.asset_code === 'USDC' && b.asset_issuer === c.usdcIssuer,
  );
  return line === undefined ? '0' : line.balance;
}

/** Fund the account with friendbot and add the USDC trustline, once. */
async function ensureFundingAccount(c: AnchorConfig, kp: Keypair): Promise<{ created: boolean; trustlineTx?: string }> {
  const server = new Horizon.Server(c.horizonUrl);
  let created = false;
  let account: Horizon.AccountResponse;
  try {
    account = await server.loadAccount(kp.publicKey());
  } catch {
    const fb = await fetch(`https://friendbot.stellar.org?addr=${kp.publicKey()}`, { signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) });
    if (!fb.ok) throw new AnchorError(`friendbot refused to fund ${kp.publicKey()}: HTTP ${fb.status}`);
    created = true;
    account = await server.loadAccount(kp.publicKey());
  }
  const hasLine = account.balances.some(
    (b) => b.asset_type !== 'native' && 'asset_code' in b && b.asset_code === 'USDC' && b.asset_issuer === c.usdcIssuer,
  );
  if (hasLine) return { created };
  const tx = new TransactionBuilder(account, { fee: '1000', networkPassphrase: c.networkPassphrase })
    .addOperation(Operation.changeTrust({ asset: usdcAsset(c) }))
    .setTimeout(60)
    .build();
  tx.sign(kp);
  const submitted = await server.submitTransaction(tx);
  return { created, trustlineTx: submitted.hash };
}

/**
 * Poll the deposit until the anchor reports it completed. The anchor's payout is its own process;
 * after `maxMs` this returns the last state seen instead of throwing, so a slow anchor ends the run
 * with an honest "pending" rather than a failure — the TRY was accepted and the USDC follows.
 */
async function waitForDeposit(
  c: AnchorConfig,
  token: string,
  id: string,
  maxMs = 150_000,
): Promise<{ tx: Record<string, unknown>; completed: boolean }> {
  const deadline = Date.now() + maxMs;
  let last: Record<string, unknown> = {};
  while (Date.now() < deadline) {
    const body = await getJson(`${c.baseUrl}/sep6/transaction?id=${encodeURIComponent(id)}`, token);
    last = (body['transaction'] ?? body) as Record<string, unknown>;
    const status = last['status'];
    if (status === 'completed') return { tx: last, completed: true };
    if (status === 'error' || status === 'refunded') {
      throw new AnchorError(`deposit ${id} ended in status ${String(status)}: ${String(last['message'] ?? '')}`);
    }
    await new Promise((r) => setTimeout(r, 3000));
  }
  return { tx: last, completed: false };
}

export async function runOnramp(
  deps: OnrampDeps,
  args: { accountId: string; walletCAddr: string; tryAmount: number; emit: EmitStep },
): Promise<OnrampResult> {
  const c = deps.anchor;
  const { emit } = args;
  const step = (s: DemoStep): void | Promise<void> => emit(s);

  /* 1. the gate decides */
  const allowed = await deps.gateAllows(args.walletCAddr);
  if (!allowed) {
    await step({
      id: 'gate',
      title: 'Gate check',
      detail: 'kyc-gate.check(wallet, OVER_18) reads false on testnet, so the anchor is not offered.',
      status: 'fail',
    });
    throw new AnchorError('the chain does not record over18 for this wallet');
  }
  await step({
    id: 'gate',
    title: 'Gate check',
    detail: 'kyc-gate.check(wallet, OVER_18) reads true on testnet: the contract, not this server, says the holder may buy.',
    status: 'ok',
    data: { wallet: args.walletCAddr },
  });

  /* 2. funding account */
  const kp = deps.fundingKeys.getOrCreate(args.accountId);
  const funded = await ensureFundingAccount(c, kp);
  await step({
    id: 'funding',
    title: 'Funding account',
    detail: funded.created
      ? 'Created a classic Stellar account for the purchase, funded by friendbot, with a USDC trustline. SEP-10 needs a key that can sign; the passkey wallet is a contract, so the USDC lands here.'
      : 'Reusing the account’s funding account; the USDC trustline is in place.',
    status: 'ok',
    ...(funded.trustlineTx === undefined ? {} : { txHash: funded.trustlineTx, explorerUrl: `${c.explorerBase}/tx/${funded.trustlineTx}` }),
    data: { account: kp.publicKey() },
  });

  /* 3. SEP-10 */
  const token = await sep10Authenticate(c, kp);
  await step({
    id: 'sep10',
    title: 'SEP-10 authentication',
    detail: 'Fetched the anchor’s challenge, verified it is signed by the anchor’s SIGNING_KEY for this network and this account, signed it, and received a session token.',
    status: 'ok',
    data: { anchor: new URL(c.baseUrl).host },
  });

  /* 4. SEP-12 */
  const customer = await postPut(`${c.baseUrl}/sep12/customer`, { first_name: 'Onramp', last_name: 'Customer' }, token);
  const kycStatus = await getJson(`${c.baseUrl}/sep12/customer`, token);
  await step({
    id: 'sep12',
    title: 'SEP-12 customer handoff',
    detail: 'Registered the funding account as a customer. Nothing from the KYC wizard is sent: the anchor relies on the on-chain verdict, and receives no document, date of birth or document number.',
    status: 'ok',
    data: { customerId: String(customer['id'] ?? ''), status: String(kycStatus['status'] ?? '') },
  });

  /* 5. SEP-38 */
  const sell = args.tryAmount.toFixed(2);
  const quote = parseQuote(
    await postJson(
      `${c.baseUrl}/sep38/quote`,
      { sell_asset: 'iso4217:TRY', buy_asset: `stellar:USDC:${c.usdcIssuer}`, sell_amount: sell, context: 'sep6' },
      token,
    ),
  );
  await step({
    id: 'sep38',
    title: 'SEP-38 firm quote',
    detail: `${quote.sellAmount} TRY buys ${quote.buyAmount} USDC at ${quote.totalPrice} TRY per USDC. The quote is single-use and expires at ${quote.expiresAt}.`,
    status: 'ok',
    data: { quoteId: quote.id, sellAmount: quote.sellAmount, buyAmount: quote.buyAmount, price: quote.totalPrice },
  });

  /* 6. SEP-6 */
  const depositUrl =
    `${c.baseUrl}/sep6/deposit?asset_code=USDC&amount=${sell}&account=${kp.publicKey()}` +
    `&funding_method=bank_account&type=bank_account&quote_id=${encodeURIComponent(quote.id)}`;
  const deposit = parseDeposit(await getJson(depositUrl, token));
  await step({
    id: 'sep6',
    title: 'SEP-6 deposit instructions',
    detail: `The anchor opened deposit ${deposit.id} and returned the bank details a customer would pay: ${deposit.bankName}, IBAN ${deposit.iban}, reference ${deposit.memo}.`,
    status: 'ok',
    data: { depositId: deposit.id, bankName: deposit.bankName, iban: deposit.iban, reference: deposit.memo },
  });

  /* 7. simulated bank transfer */
  await postJson(`${c.baseUrl}/sep6/tx/${encodeURIComponent(deposit.id)}/simulate-bank-transfer`, { amount: sell });
  await step({
    id: 'bank',
    title: 'Bank transfer (simulated)',
    detail: 'The sandbox anchor marks the TRY as received. In production this is the customer’s bank transfer with the reference above.',
    status: 'ok',
    data: { amountTry: sell },
  });

  /* 8. USDC on chain */
  const outcome = await waitForDeposit(c, token, deposit.id);
  const stellarTx = String(outcome.tx['stellar_transaction_id'] ?? '');
  const balance = await usdcBalance(c, kp.publicKey());
  await step({
    id: 'usdc',
    title: 'USDC on testnet',
    detail: outcome.completed
      ? `The anchor paid ${quote.buyAmount} USDC from its treasury to the funding account. Balance now ${balance} USDC.`
      : `The anchor accepted the TRY and reports "${String(outcome.tx['message'] ?? outcome.tx['status'] ?? 'pending')}". Its payout has not landed yet; the balance updates on this page once it does (deposit ${deposit.id}).`,
    status: outcome.completed ? 'ok' : 'pending',
    ...(stellarTx.length === 0 ? {} : { txHash: stellarTx, explorerUrl: `${c.explorerBase}/tx/${stellarTx}` }),
    data: { usdcBalance: balance, fundingAccount: kp.publicKey(), depositId: deposit.id, anchorStatus: String(outcome.tx['status'] ?? '') },
  });

  return {
    fundingAccount: kp.publicKey(),
    tryAmount: quote.sellAmount,
    usdcAmount: quote.buyAmount,
    quoteId: quote.id,
    depositId: deposit.id,
    stellarTxHash: stellarTx,
    usdcBalance: balance,
  };
}

async function postPut(url: string, payload: unknown, token: string): Promise<Record<string, unknown>> {
  const res = await fetch(url, {
    method: 'PUT',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
    body: JSON.stringify(payload),
    signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
  });
  const body = (await res.json().catch(() => null)) as Record<string, unknown> | null;
  if (!res.ok || body === null) {
    throw new AnchorError(`${new URL(url).pathname}: HTTP ${res.status} ${JSON.stringify(body).slice(0, 200)}`);
  }
  return body;
}

/** The dashboard's read-only view: funding account and USDC balance, if any. */
export async function readOnrampState(
  deps: OnrampDeps,
  accountId: string,
): Promise<{ fundingAccount: string | null; usdcBalance: string | null }> {
  const kp = deps.fundingKeys.get(accountId);
  if (kp === undefined) return { fundingAccount: null, usdcBalance: null };
  try {
    return { fundingAccount: kp.publicKey(), usdcBalance: await usdcBalance(deps.anchor, kp.publicKey()) };
  } catch {
    return { fundingAccount: kp.publicKey(), usdcBalance: null };
  }
}
