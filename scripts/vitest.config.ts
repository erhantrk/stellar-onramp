import { defineConfig } from 'vitest/config';

/** The demo server's own tests: anchor protocol handling, no network. */
export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    environment: 'node',
  },
});
