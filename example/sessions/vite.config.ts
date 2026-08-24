import fs from "node:fs";
import path from "node:path";
import { defineConfig, type Plugin } from "vite";
import vue from "@vitejs/plugin-vue";
import tailwindcss from "@tailwindcss/vite";

const hotFile = path.join(import.meta.dirname, "public", "hot");

// The FastAPI side serves dev-server asset tags when public/hot exists (its
// content is the dev origin) and built assets otherwise — the same convention
// as laravel-vite-plugin. Vite's default dev CORS policy already allows
// localhost origins, so the page on :8000 can load from the dev server.
function startkitHotFile(): Plugin {
  const removeHotFile = () => {
    fs.rmSync(hotFile, { force: true });
  };
  return {
    name: "startkit-hot-file",
    apply: "serve",
    configureServer(server) {
      server.httpServer?.once("listening", () => {
        const address = server.httpServer?.address();
        if (address && typeof address === "object") {
          fs.mkdirSync(path.dirname(hotFile), { recursive: true });
          fs.writeFileSync(hotFile, `http://localhost:${address.port}`);
        }
      });
      process.on("exit", removeHotFile);
      for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) {
        process.on(signal, () => process.exit());
      }
    },
  };
}

export default defineConfig({
  plugins: [vue(), tailwindcss(), startkitHotFile()],
  // Assets are emitted into public/build; there is no static passthrough dir,
  // so disable Vite's default `public/` handling to avoid overlap.
  publicDir: false,
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
