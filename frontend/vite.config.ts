import { resolve } from "node:path"
import tailwindcss from "@tailwindcss/vite"
import react from "@vitejs/plugin-react"
import { defineConfig } from "vite"

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  base: "/static/ui/",
  build: {
    outDir: "../src/penrecon/web/static/ui",
    emptyOutDir: true,
    cssCodeSplit: false,
    rollupOptions: {
      // The HTML cache-busts app.js with a query string. Keep its exports closed
      // so lazy chunks share hashed modules instead of reimporting the entry.
      preserveEntrySignatures: "strict",
      input: resolve(import.meta.dirname, "src/main.tsx"),
      output: {
        entryFileNames: "app.js",
        chunkFileNames: "[name]-[hash].js",
        assetFileNames: (asset) => asset.names.some(name => name.endsWith(".css")) ? "app.css" : "[name]-[hash][extname]",
      },
    },
  },
  resolve: {
    alias: {
      "@": resolve(import.meta.dirname, "./src"),
    },
  },
})
