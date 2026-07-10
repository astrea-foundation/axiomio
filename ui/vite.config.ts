import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// Tauri expects a fixed dev port and relative asset paths.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  base: "./",
  clearScreen: false,
  server: { port: 5273, strictPort: true },
  build: { outDir: "dist", emptyOutDir: true, target: "es2021" },
});
