import { defineConfig } from 'vitest/config';

/**
 * Package-level vitest config. The root vitest.config.ts lists projects:['packages/*','apps/*'], so
 * this file is what `npx vitest run` from the repo root resolves for this package — no root change
 * is needed to pick it up, and the observable proof that it WAS resolved is the
 * `@stellaronramp/gateway-http` project label on every test line in the root run's output.
 *
 * Do NOT restate the timeout as `vi.setConfig(...)` in the test files; the root config comment
 * documents why that duplication was removed from packages/identity.
 */
export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    environment: 'node',
    // The http-integration suite spins up a real node:http server on port 0 and drives it with
    // globalThis.fetch; BBS+ issuance reaches into pure-JS BLS12-381. 60 s matches the libraries.
    testTimeout: 60_000,
    hookTimeout: 60_000,
  },
});
