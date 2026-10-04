import tailwindcss from '@tailwindcss/postcss';
import react from '@vitejs/plugin-react';
import { fileURLToPath, URL } from 'node:url';
import { defineConfig } from 'vite';
// Static console; authentication and private data are served by the Rust API.
export default defineConfig({
  css: { postcss: { plugins: [tailwindcss()] } },
  resolve: { alias: { '@': fileURLToPath(new URL('.', import.meta.url)) } },
  build: { outDir: 'dist/client', emptyOutDir: true },
  server: {
    host: '127.0.0.1',
    watch: { usePolling: true },
    proxy: { '/api': 'http://127.0.0.1:18080' },
  },
  plugins: [react()],
});
