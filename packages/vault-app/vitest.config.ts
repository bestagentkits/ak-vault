import { defineConfig } from 'vitest/config';

// Node by default (WebCrypto Ed25519/X25519, esbuild); DOM tests opt in with
// `// @vitest-environment happy-dom`.
export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    testTimeout: 60_000,
  },
});
