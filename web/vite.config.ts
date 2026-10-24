import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'
import { tanstackRouter } from '@tanstack/router-plugin/vite'
import { fileURLToPath } from 'node:url'

// A running `porch serve` (development mode) for `pnpm dev`.
const api = process.env.PORCH_API ?? 'http://127.0.0.1:8080'

export default defineConfig({
  plugins: [tanstackRouter({ target: 'react', autoCodeSplitting: true }), react()],
  resolve: { alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) } },
  build: {
    // Embedded into the Go binary (internal/webui). public/README.txt is copied back after emptyOutDir so the
    // placeholder that keeps `go:embed all:dist` compiling survives every build.
    outDir: '../internal/webui/dist',
    emptyOutDir: true,
    chunkSizeWarningLimit: 1500,
    // CSP forbids data: fonts/scripts; keep every asset a separate file.
    assetsInlineLimit: 0,
  },
  server: { proxy: { '/api': api, '/login/': api, '/oauth2': api, '/.well-known': api } },
  test: {
    globals: true,
    environment: 'jsdom',
    setupFiles: ['./src/test/setup.ts'],
    include: ['src/**/*.test.{ts,tsx}'],
  },
})
