import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  clearScreen: false,
  server: {
    port: 1421,
    strictPort: false,
    watch: {
      ignored: [
        '**/src-tauri/**',
        '**/data/**',
        '**/logs/**',
        '**/config/scan_cache.json',
        '**/config/quarantine_index.json',
        '**/config/startup_allowlist.enc',
        '**/data/runtime/**',
      ],
    },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
  },
})
