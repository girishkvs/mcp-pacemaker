import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// Built to ui/dist and served by the bridge at /ui. In dev, /api + /admin proxy to a running bridge.
export default defineConfig({
  plugins: [react()],
  base: '/ui/',
  build: { outDir: 'dist', emptyOutDir: true },
  server: {
    port: 5173,
    proxy: {
      '/api': 'http://127.0.0.1:8791',
      '/admin': 'http://127.0.0.1:8791',
    },
  },
});
