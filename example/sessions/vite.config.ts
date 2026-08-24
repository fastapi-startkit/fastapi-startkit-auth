import { defineConfig } from "vite";
import vue from "@vitejs/plugin-vue";
import tailwindcss from "@tailwindcss/vite";
import fastapi from "fastapi-vite-plugin";

// fastapi-vite-plugin owns the build output/manifest layout and the
// public/hot dev-server handshake expected by the framework's ViteProvider.
export default defineConfig({
  plugins: [
    fastapi({
      input: "resources/js/app.ts",
      refresh: true,
    }),
    vue(),
    tailwindcss(),
  ],
});
