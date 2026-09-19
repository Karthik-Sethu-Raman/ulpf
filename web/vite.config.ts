import react from '@vitejs/plugin-react'
import { defineConfig } from 'vitest/config'

// Dev proxy: same-origin /api in the browser, forwarded to the gateway
// (services/gateway, default :8000). In production Caddy does this instead —
// no CORS anywhere (the gateway deliberately ships none).
// test.environment stays "node"; the one DOM-dependent test opts into jsdom
// via a `@vitest-environment jsdom` docblock.
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/api': 'http://localhost:8000',
    },
  },
  test: {
    environment: 'node',
  },
})
