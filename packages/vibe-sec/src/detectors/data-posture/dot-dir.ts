// Dot-directory filter for the data-posture walks (GAP-09).
//
// The shared source-walk skips node_modules/dist/.git etc. but not dot
// directories generally. Data-posture evidence from a dot directory is either
// a duplicate checkout (.worktrees/<branch>/ carries a full copy of the repo —
// observed on Project-626Labs-1, where every migration site triple-counted) or
// tooling state (.firebase/, .vibe-*/), never the shipped data layer. Scoped
// here rather than widening the shared walker: the other structural detectors
// have their own calibration and changing their walk is not this concern's call.

/** True when any path segment starts with a dot (".worktrees/x/y.ts", ".firebase/…"). */
export function inDotDir(rel: string): boolean {
  return rel.split("/").some((seg) => seg.startsWith("."));
}
