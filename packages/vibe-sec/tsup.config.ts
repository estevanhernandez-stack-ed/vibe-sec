import { defineConfig } from "tsup";

// Vibe Sec v0.2 build.
//   - index: the library surface, dual ESM + CJS for broad consumption.
//   - cli:   the headless-CI binary. ESM-only — it uses import.meta.url for
//            the run-as-main guard, which is empty in CJS. The bin field
//            points at dist/cli.js (ESM), so ESM-only is correct and keeps the
//            build warning-free.
export default defineConfig([
  {
    entry: { index: "src/index.ts" },
    format: ["esm", "cjs"],
    target: "node20",
    dts: true,
    clean: true,
    sourcemap: true,
    splitting: false,
  },
  {
    entry: { cli: "src/cli.ts" },
    format: ["esm"],
    target: "node20",
    dts: true,
    clean: false,
    sourcemap: true,
    splitting: false,
  },
]);
