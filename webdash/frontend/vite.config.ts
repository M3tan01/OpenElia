import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { resolve } from "path";

// Build output goes to ../static so FastAPI serves the SPA same-origin in prod.
// In dev, `npm run dev` proxies /api + /healthz to the FastAPI server on :8765.
export default defineConfig({
  plugins: [react()],
  build: {
    outDir: resolve(__dirname, "../static"),
    emptyOutDir: true,
  },
  server: {
    port: 5173,
    proxy: {
      "/api": { target: "http://127.0.0.1:8765", changeOrigin: true, ws: true },
      "/healthz": "http://127.0.0.1:8765",
    },
  },
});
