# Vibe Sec Workspace — Changelog

This is the workspace-level changelog. Per-package changelogs live at:

- `packages/vibe-sec/CHANGELOG.md` — plugin changes (TBD; plugin is currently a reservation stub)
- `packages/vibe-sec-cli/CHANGELOG.md` — CLI changes (TBD; first entry once first post-migration release lands)

## 2026-04-19 — Solo repo extracted from monorepo

Vibe Sec moved from `github.com/estevanhernandez-stack-ed/vibe-plugins/packages/vibe-sec*` into its own solo repo to support the canary / stable two-channel release model.

- Full commit history preserved via `git filter-repo` (4 commits + 2 tags: `vibe-sec-v0.0.1` for the package reservation stub, `vibe-sec-cli-v0.1.0` for the first shipping CLI release)
- Workspace root added (`package.json`, `pnpm-workspace.yaml`, `.gitignore`, `.claude-plugin/marketplace.json` for canary-channel install)
- Package metadata (`repository.url`, `homepage`, `bugs`) updates happen in a follow-up `v0.1.1` / `v0.0.2` commit after the initial push lands

Current state of the plugin is still stub-only; the CLI is the first shipping capability. The plugin proper builds out from here per `packages/vibe-sec/framework.md`.
