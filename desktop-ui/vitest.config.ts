import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";
import { buildInfo } from "./scripts/build-info.mjs";

export default defineConfig({
  plugins: [react()],
  define: buildInfo,
  test: { environment: "jsdom", css: false },
});
