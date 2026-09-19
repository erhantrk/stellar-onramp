import { defineConfig } from 'vitest/config';

/**
 * Package-level vitest config, resolved by the root config's `projects` list. `include` is the
 * whole `test/` tree, so a new subdirectory of suites needs no change here.
 */
export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    environment: 'node',
    // Most suites here are pure byte-shuffling, but anything reaching through
    // @stellaronramp/identity runs pure-JS BLS12-381, which is slow.
    testTimeout: 60_000,
    hookTimeout: 60_000,
  },
});
