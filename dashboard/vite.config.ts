import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

const target = "http://localhost:8787";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  build: { outDir: "dist", sourcemap: false, chunkSizeWarningLimit: 1200 },
  server: {
    proxy: {
      "/console": { target, changeOrigin: true, ws: true },
      "/v1": { target, changeOrigin: true, ws: true },
    },
  },
});
