import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    environment: 'node',
    // BBS+ ProofGen/ProofVerify are pure-JS BLS12-381; a few hundred proofs in the
    testTimeout: 60_000,
    hookTimeout: 60_000,
  },
});
