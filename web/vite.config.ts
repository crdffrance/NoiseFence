import tailwindcss from '@tailwindcss/postcss';
import vinext from 'vinext';
import { defineConfig } from 'vite';
// Self-hosted static console. Sessions and private data belong to the Rust API.
export default defineConfig({
  css: { postcss: { plugins: [tailwindcss()] } },
  server: {
    host: '127.0.0.1',
    watch: { usePolling: true },
    proxy: { '/api': 'http://127.0.0.1:18080' },
  },
  plugins: [vinext()],
});
