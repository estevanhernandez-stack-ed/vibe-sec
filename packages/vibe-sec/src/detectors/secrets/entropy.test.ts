import { describe, it, expect } from "vitest";
import {
  shannonEntropy,
  isHighEntropyToken,
  scanEntropy,
  MIN_TOKEN_LENGTH,
} from "./entropy.js";

// Build a high-entropy base64-ish token at runtime (never a literal that trips
// push-protection). 40 mixed chars across the base64 alphabet.
const HIGH_B64 = "aZ9bQ2wE7rT4yU8iO1pK3sD6fG0hJ5lXcVbNmM2";
const HIGH_HEX = "deadbeefcafef00d0123456789abcdef01234567";
const LOW_REPEAT = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"; // 40 'a' → low entropy

describe("shannonEntropy", () => {
  it("returns 0 for empty, low for repeated chars, high for mixed", () => {
    expect(shannonEntropy("")).toBe(0);
    expect(shannonEntropy(LOW_REPEAT)).toBeLessThan(1);
    expect(shannonEntropy(HIGH_B64)).toBeGreaterThan(4.5);
  });
});

describe("isHighEntropyToken", () => {
  it("flags a high-entropy base64-ish token over the length floor", () => {
    expect(isHighEntropyToken(HIGH_B64)).toBe(true);
  });

  it("flags a high-entropy hex token at the lower 3.0 bar", () => {
    expect(isHighEntropyToken(HIGH_HEX)).toBe(true);
  });

  it("does not flag a low-entropy repeated string", () => {
    expect(isHighEntropyToken(LOW_REPEAT)).toBe(false);
  });

  it("does not flag tokens under the length floor", () => {
    expect(isHighEntropyToken("aZ9bQ2wE")).toBe(false); // 8 chars < MIN
    expect(MIN_TOKEN_LENGTH).toBe(20);
  });
});

describe("scanEntropy", () => {
  it("flags a high-entropy value assigned to a secret-shaped name", () => {
    const text = `const sessionSecret = "${HIGH_B64}";`;
    const findings = scanEntropy(text, "config.ts");
    expect(findings).toHaveLength(1);
    expect(findings[0]!.pattern).toBe("HIGH_ENTROPY_ASSIGN");
    expect(findings[0]!.match).not.toBe(HIGH_B64); // masked
  });

  it("ignores high-entropy values NOT in secret-shaped assignment", () => {
    // A high-entropy value assigned to a non-secret name → no entropy finding.
    const text = `const colorPalette = "${HIGH_B64}";`;
    expect(scanEntropy(text, "theme.ts")).toHaveLength(0);
  });

  it("ignores low-entropy values even in secret-shaped assignment", () => {
    const text = `const apiSecret = "${LOW_REPEAT}";`;
    expect(scanEntropy(text, "config.ts")).toHaveLength(0);
  });
});
