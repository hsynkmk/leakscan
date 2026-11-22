import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  plugins: [vue()],
  build: {
    // The Go binary embeds this folder (see internal/ui).
    outDir: '../internal/ui/dist',
    emptyOutDir: false, // keep .gitkeep
  },
  server: {
    // During development, forward API calls to `leakscan serve`.
    proxy: { '/api': 'http://localhost:8080' },
  },
})
