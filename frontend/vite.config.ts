import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The backend runs in a sibling container / on port 8000 locally. Proxying keeps
// the browser on one origin, so the app works unchanged whether it is served by
// the dev server or from a static build behind a reverse proxy.
const BACKEND = process.env.BACKEND_ORIGIN ?? "http://localhost:8000";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    host: true,
    proxy: {
      "/api": { target: BACKEND, changeOrigin: true },
    },
  },
});
