import { defineConfig } from "vite";
import vue from "@vitejs/plugin-vue";

export default defineConfig({
  plugins: [vue()],
  build: {
    // The FastAPI side reads this manifest to resolve hashed asset URLs and
    // to derive the Inertia asset version.
    manifest: true,
    outDir: "public/build",
    rollupOptions: {
      input: "resources/js/app.ts",
    },
  },
});
