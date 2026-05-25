import { defineConfig } from "tsup";

// @esthernandez/vibe-sec-cli — self-contained bundle build.
//
// bundle:true with noExternal:[/(.*)/] inlines EVERY dependency — @babel/parser,
// @babel/types, and the whole detector engine pulled in transitively from the
// workspace @esthernandez/vibe-sec source — so the published dist/cli.js runs
// standalone with zero runtime dependencies. The plugin package's own build
// leaves @babel external (it ships them as deps); this one does not.
//
// ESM-only: the upstream cli.ts run-as-main guard is format-agnostic (basename
// comparison, not import.meta / require.main), so ESM is correct and the bin
// field points at dist/cli.js.
export default defineConfig({
  entry: { cli: "src/cli.ts" },
  format: ["esm"],
  target: "node20",
  bundle: true,
  // Inline everything. tsup externalizes deps by default; force all into the bundle.
  noExternal: [/.*/],
  dts: false,
  clean: true,
  sourcemap: true,
  splitting: false,
  // No banner: the upstream src/cli.ts already carries the shebang as line 1,
  // and esbuild preserves it. Adding a banner here would double it.
});
