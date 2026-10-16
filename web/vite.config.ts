import tailwindcss from '@tailwindcss/postcss';
import react from '@vitejs/plugin-react';
import { fileURLToPath, URL } from 'node:url';
import { defineConfig } from 'vite';
import { consoleIdentity } from './build-identity.mjs';
const identity = consoleIdentity(fileURLToPath(new URL('.', import.meta.url)));
// Static console; authentication and private data are served by the Rust API.
export default defineConfig({
  define: { __NOISEFENCE_CONSOLE__: JSON.stringify(identity) },
  css: { postcss: { plugins: [tailwindcss()] } },
  resolve: { alias: { '@': fileURLToPath(new URL('.', import.meta.url)) } },
  build: { outDir: 'dist/client', emptyOutDir: true },
  server: {
    host: '127.0.0.1',
    watch: { usePolling: true },
    proxy: { '/api': 'http://127.0.0.1:18080' },
  },
  plugins: [react(), {
    name: 'noisefence-console-identity',
    generateBundle() { this.emitFile({ type: 'asset', fileName: 'version.json', source: JSON.stringify(identity) + '\n' }); },
  }],
});
