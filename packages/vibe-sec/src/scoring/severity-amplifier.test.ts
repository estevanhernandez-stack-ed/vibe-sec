import { describe, it, expect } from "vitest";
import { amplify, capForSeverity, CRITICAL_CAP, HIGH_CAP } from "./severity-amplifier.js";

describe("severity amplifier", () => {
  it("caps a 0.97-clean concern with one Critical at 0.5", () => {
    expect(amplify(0.97, ["critical"])).toBe(CRITICAL_CAP);
    expect(amplify(0.97, ["critical"])).toBe(0.5);
  });

  it("caps a near-clean concern with one High at 0.8", () => {
    expect(amplify(0.95, ["high"])).toBe(HIGH_CAP);
    expect(amplify(0.95, ["high"])).toBe(0.8);
  });

  it("Critical wins over High when both present", () => {
    expect(amplify(0.99, ["high", "critical"])).toBe(0.5);
  });

  it("Medium/Low findings do not amplify — raw fraction passes through", () => {
    expect(amplify(0.6, ["medium", "low"])).toBe(0.6);
    expect(amplify(0.42, [])).toBe(0.42);
  });

  it("never raises the value above the raw fraction", () => {
    // A clean 0.3 concern with a High caps at 0.8 but the raw 0.3 already lower.
    expect(amplify(0.3, ["high"])).toBe(0.3);
  });

  it("clamps out-of-range and NaN inputs", () => {
    expect(amplify(1.5, [])).toBe(1);
    expect(amplify(-0.2, [])).toBe(0);
    expect(amplify(Number.NaN, [])).toBe(0);
  });

  it("capForSeverity exposes the per-severity cap", () => {
    expect(capForSeverity("critical")).toBe(0.5);
    expect(capForSeverity("high")).toBe(0.8);
    expect(capForSeverity("medium")).toBe(1);
    expect(capForSeverity("low")).toBe(1);
  });
});
