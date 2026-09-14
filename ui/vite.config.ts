import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from 'tailwindcss';
import autoprefixer from 'autoprefixer';
import { bundledNotices } from '../tools/third-party-notices/vite-plugin.mjs';

const notices = bundledNotices();

// Built to ui/dist and served by the bridge at /ui. In dev, /api + /admin proxy to a running bridge.
export default defineConfig({
  plugins: [react(), notices.vitePlugin],
  css: {
    postcss: { plugins: [notices.cssPlugin, tailwindcss(), autoprefixer()] },
  },
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
