import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Built assets are served by the Python app at /v2/ (see threatweaver/app/api.py).
export default defineConfig({
  base: "/v2/",
  plugins: [react()],
  build: {
    outDir: "../src/threatweaver/app/static/v2",
    emptyOutDir: true,
    sourcemap: false,
    chunkSizeWarningLimit: 600,
  },
  server: {
    // Dev only: proxy API calls to a running `threatweaver ui` on 8765.
    proxy: { "/api": "http://127.0.0.1:8765" },
  },
});
