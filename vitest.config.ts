import { defineConfig } from 'vitest/config';

/**
 * Root vitest config: `npx vitest run` from the repo root resolves each workspace's own
 * vitest.config.ts (timeouts, includes) instead of running everything on defaults. Every glob in
 * the root package.json `workspaces` array is listed here, plus the demo server's tests.
 */
export default defineConfig({
  test: {
    projects: ['packages/*', 'apps/*', 'scripts'],
  },
});
