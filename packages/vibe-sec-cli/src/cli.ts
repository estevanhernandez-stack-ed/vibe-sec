#!/usr/bin/env node
// @esthernandez/vibe-sec-cli — self-contained headless audit binary.
//
// This package re-bundles the SAME CLI the plugin package (@esthernandez/vibe-sec)
// builds from packages/vibe-sec/src/cli.ts, but with bundle:true so every
// transitive dependency (@babel/parser, @babel/types, the full detector engine)
// is inlined into dist/cli.js. The published artifact runs standalone with zero
// runtime dependencies — there is no install-time dependency on
// @esthernandez/vibe-sec (which is being deprecated on npm).
//
// We import runCli + VERSION directly from the plugin package's TypeScript
// source via the workspace relative path so esbuild walks and inlines the
// whole graph. The exit-code contract is owned upstream in cli.ts:
//   0 — clean, or findings below --min-severity
//   1 — findings at or above --min-severity
//   2 — scanner error (unreadable tree, invalid args, etc.)
//
// Defers to gitleaks/trufflehog when present; in-house Layer A/B/C otherwise.

import { runCli } from "../../vibe-sec/src/cli.js";

process.exit(runCli(process.argv));
