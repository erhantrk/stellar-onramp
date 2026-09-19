import { defineConfig } from 'vitest/config';

/**
 * Root vitest config: `npx vitest run` from the repo root resolves each workspace's own
 * vitest.config.ts (timeouts, includes) instead of running everything on vitest's defaults.
 * Every glob in the root package.json `workspaces` array is listed here.
 */
export default defineConfig({
  test: {
    // Each entry resolves that directory's own vitest.config.ts. This list MUST cover every glob
    // in the root package.json `workspaces` array — a package added there but not here runs on
    // vitest's defaults from the root, which is the exact failure this file exists to prevent.
    // `apps/*` matches nothing on disk today and is listed anyway, for that reason; vitest is fine
    // with a glob that matches no directory (verified, not assumed). A test in
    projects: ['packages/*', 'apps/*'],
  },
});
