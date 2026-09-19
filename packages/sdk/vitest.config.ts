import { defineConfig } from 'vitest/config';

/** Package-level vitest config, resolved by the root config's `projects` list. */
export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    environment: 'node',
    // The mocked-RPC HTTP servers wait on local I/O, and proof work runs pure-JS BLS12-381.
    testTimeout: 60_000,
    hookTimeout: 60_000,
  },
});
