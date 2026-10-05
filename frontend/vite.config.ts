import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Build straight into the Go gateway's embedded dir. During `npm run dev`
// the API is proxied to the running gateway so there is no CORS friction.
export default defineConfig({
  plugins: [react()],
  build: {
    outDir: "../cmd/gateway/dist",
    emptyOutDir: true,
  },
  server: {
    port: 5173,
    proxy: {
      "/v1": "http://localhost:8080",
    },
  },
});