import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// In the compose network the API is reachable at http://api:8001. For host-
// dev (`npm run dev`) it's on http://127.0.0.1:8001. Same-origin calls are
// routed through /api/* at build time so nginx can proxy in the container.
export default defineConfig({
  plugins: [react()],
  server: {
    host: "127.0.0.1",
    port: 3000,
    proxy: {
      "/api": {
        target: "http://127.0.0.1:8001",
        changeOrigin: true,
        rewrite: (p) => p.replace(/^\/api/, ""),
      },
    },
  },
  build: {
    outDir: "dist",
    sourcemap: false,
  },
});
