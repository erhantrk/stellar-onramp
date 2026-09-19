/**
 * `loadSdkConfig` — fail-closed on everything, and the failures happen HERE rather than at the
 * first factory call. The repo's real deployments.json is deliberately NOT read by these tests:
 * a test that depends on the repo-root deployment state breaks the day a deploy is added. Every
 * case runs against a fixture file in a temp dir.
 */

import { mkdtempSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { SdkConfigError, loadSdkConfig } from '../src/index.js';

function configDir(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), 'sdk-config-'));
  for (const [name, content] of Object.entries(files)) {
    writeFileSync(join(dir, name), content);
  }
  return dir;
}

const GATE = 'CABAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAFNSZ';
const REGISTRY = 'CAAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQC526';

const VALID = JSON.stringify({
  testnet: {
    networkPassphrase: 'Test SDF Network ; September 2015',
    networkConfig: { rpcUrl: 'https://soroban-testnet.stellar.org' },
    contracts: {
      'kyc-gate': { id: GATE },
      'kyc-registry': { id: REGISTRY },
    },
  },
});

describe('loadSdkConfig', () => {
  it('loads the happy path from a deployments file', () => {
    const cfg = loadSdkConfig('testnet', {
      deploymentsPath: join(configDir({ 'deployments.json': VALID }), 'deployments.json'),
    });
    expect(cfg).toEqual({
      network: 'testnet',
      networkPassphrase: 'Test SDF Network ; September 2015',
      rpcUrl: 'https://soroban-testnet.stellar.org',
      kycGateContractId: GATE,
      kycRegistryContractId: REGISTRY,
    });
  });

  it("FAILS CLOSED on an unknown env name — a typo must not silently pick a network", () => {
    expect(() =>
      loadSdkConfig('staging', {
        deploymentsPath: join(configDir({ 'deployments.json': VALID }), 'deployments.json'),
      }),
    ).toThrow(SdkConfigError);
  });

  it('FAILS CLOSED when the deployments file is missing — never hands out an empty config', () => {
    expect(() =>
      loadSdkConfig('testnet', { deploymentsPath: join(tmpdir(), 'no-such-deployments-here.json') }),
    ).toThrow(SdkConfigError);
  });

  it('FAILS CLOSED on malformed JSON', () => {
    const dir = configDir({ 'deployments.json': '{ not json' });
    expect(() =>
      loadSdkConfig('testnet', { deploymentsPath: join(dir, 'deployments.json') }),
    ).toThrow(SdkConfigError);
  });

  it('FAILS CLOSED on the mainnet case: contracts present but EMPTY ids', () => {
    // The literal shape of the repo's mainnet block today: no contracts key at all.
    const mainnet = JSON.stringify({
      mainnet: {
        networkPassphrase: 'Public Global Stellar Network ; September 2015',
        networkConfig: { rpcUrl: 'https://mainnet.sorobanrpc.com' },
      },
    });
    const dir = configDir({ 'deployments.json': mainnet });
    expect(() =>
      loadSdkConfig('mainnet', { deploymentsPath: join(dir, 'deployments.json') }),
    ).toThrow(/kyc-gate/);
  });

  it('FAILS CLOSED on a contract id that is not a C-strkey', () => {
    // The shape of the incident this guard exists for: a plausible-looking id that is not real.
    // the test passed via the missing-registry guard and the strkey regex was never exercised.
    // This id is the right LENGTH (C + 55) but '1' is outside base32 [A-Z2-7], so ONLY the
    // strkey gate can reject it — every other contract id is present and valid.
    const poisoned = JSON.stringify({
      testnet: {
        networkPassphrase: 'Test SDF Network ; September 2015',
        networkConfig: { rpcUrl: 'https://soroban-testnet.stellar.org' },
        contracts: {
          'kyc-gate': { id: `C${'1'.repeat(55)}` },
          'kyc-registry': { id: REGISTRY },
        },
      },
    });
    const dir = configDir({ 'deployments.json': poisoned });
    expect(() =>
      loadSdkConfig('testnet', { deploymentsPath: join(dir, 'deployments.json') }),
    ).toThrow(SdkConfigError);
  });

  it('FAILS CLOSED on a missing networkPassphrase', () => {
    const dir = configDir({
      'deployments.json': JSON.stringify({
        testnet: {
          networkConfig: { rpcUrl: 'https://soroban-testnet.stellar.org' },
          contracts: { 'kyc-gate': { id: GATE }, 'kyc-registry': { id: REGISTRY } },
        },
      }),
    });
    expect(() =>
      loadSdkConfig('testnet', { deploymentsPath: join(dir, 'deployments.json') }),
    ).toThrow(SdkConfigError);
  });

  it('refuses a plain-http rpcUrl unless allowInsecureRpc is explicit', () => {
    const http = JSON.stringify({
      testnet: {
        networkPassphrase: 'Test SDF Network ; September 2015',
        networkConfig: { rpcUrl: 'http://127.0.0.1:8000/soroban/rpc' },
        contracts: { 'kyc-gate': { id: GATE }, 'kyc-registry': { id: REGISTRY } },
      },
    });
    const dir = configDir({ 'deployments.json': http });
    expect(() =>
      loadSdkConfig('testnet', { deploymentsPath: join(dir, 'deployments.json') }),
    ).toThrow(/https/);
    expect(() =>
      loadSdkConfig('testnet', {
        deploymentsPath: join(dir, 'deployments.json'),
        allowInsecureRpc: true,
      }),
    ).not.toThrow();
  });

  it('the repo deployments.json resolves from the default path', () => {
    // Loads when the contracts are deployed; fails closed (never an empty config) when the ids
    // are not filled in yet. Either way the default path must land on the repo root.
    try {
      const cfg = loadSdkConfig('testnet');
      expect(cfg.kycGateContractId).toMatch(/^C[A-Z2-7]{55}$/);
      expect(cfg.networkPassphrase).toBe('Test SDF Network ; September 2015');
    } catch (err) {
      expect(err).toBeInstanceOf(SdkConfigError);
    }
    expect(() => loadSdkConfig('mainnet')).toThrow(SdkConfigError);
  });
});
