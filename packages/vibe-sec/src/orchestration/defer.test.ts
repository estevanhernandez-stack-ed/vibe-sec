import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  detectToolOfRecord,
  SECRET_TOOL_CANDIDATES,
  type ToolProbe,
} from "./tool-registry.js";
import {
  parseGitleaksJson,
  parseTrufflehogJsonl,
  type CommandRunner,
} from "./defer.js";
import { scanSecrets } from "../detectors/secrets/index.js";

let tmp: string;
beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "vibe-sec-defer-"));
});
afterEach(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

const AWS = "AKIA" + "ABCDEFGHIJ234567";

function writeAwsLeak(): void {
  fs.writeFileSync(path.join(tmp, "config.js"), `const k = "${AWS}";`, "utf8");
}

// Mock probes.
const gitleaksPresent: ToolProbe = (tool) => ({
  name: tool,
  present: tool === "gitleaks",
  version: tool === "gitleaks" ? "8.18.0" : null,
});
const noToolsPresent: ToolProbe = (tool) => ({ name: tool, present: false, version: null });

describe("tool-of-record detection", () => {
  it("detects gitleaks first when present (priority order)", () => {
    const presence = detectToolOfRecord(SECRET_TOOL_CANDIDATES, gitleaksPresent);
    expect(presence?.name).toBe("gitleaks");
    expect(presence?.version).toBe("8.18.0");
  });

  it("returns null when no candidate tool is present", () => {
    expect(detectToolOfRecord(SECRET_TOOL_CANDIDATES, noToolsPresent)).toBeNull();
  });
});

describe("gitleaks JSON adapter", () => {
  it("parses gitleaks findings into the neutral shape", () => {
    const json = JSON.stringify([
      {
        RuleID: "aws-access-key",
        File: "src\\config.js",
        StartLine: 12,
        StartColumn: 11,
        Secret: AWS,
        Match: `const k = "${AWS}"`,
        Description: "AWS Access Key",
      },
    ]);
    const findings = parseGitleaksJson(json);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe("critical"); // aws → critical
    expect(findings[0]!.file).toBe("src/config.js"); // backslash normalized
    expect(findings[0]!.match).not.toBe(AWS); // masked
    expect(findings[0]!.line).toBe(12);
  });

  it("returns [] on unparseable gitleaks output", () => {
    expect(parseGitleaksJson("not json")).toEqual([]);
  });
});

describe("trufflehog JSONL adapter", () => {
  it("marks verified findings critical", () => {
    const jsonl = [
      JSON.stringify({
        DetectorName: "AWS",
        Raw: AWS,
        Verified: true,
        SourceMetadata: { Data: { Filesystem: { file: "a.ts", line: 3 } } },
      }),
      JSON.stringify({
        DetectorName: "Generic",
        Raw: "maybe",
        Verified: false,
        SourceMetadata: { Data: { Filesystem: { file: "b.ts", line: 9 } } },
      }),
    ].join("\n");
    const findings = parseTrufflehogJsonl(jsonl);
    expect(findings).toHaveLength(2);
    expect(findings[0]!.severity).toBe("critical");
    expect(findings[1]!.severity).toBe("high");
  });
});

describe("scanSecrets orchestration", () => {
  it("takes the deferral path when gitleaks is present (mocked)", () => {
    writeAwsLeak();
    const fakeRunner: CommandRunner = (cmd) => {
      expect(cmd).toBe("gitleaks");
      return JSON.stringify([
        {
          RuleID: "aws-access-key",
          File: "config.js",
          StartLine: 1,
          StartColumn: 11,
          Secret: AWS,
          Match: `const k = "${AWS}"`,
        },
      ]);
    };
    const result = scanSecrets(tmp, { probe: gitleaksPresent, runner: fakeRunner });
    expect(result.deferred).toBe(true);
    expect(result.toolOfRecord).toBe("gitleaks");
    expect(result.findings).toHaveLength(1);
    expect(result.filesScanned).toBe(-1); // external = n/a
  });

  it("falls back to in-house Layer A when no tool is present", () => {
    writeAwsLeak();
    const result = scanSecrets(tmp, { probe: noToolsPresent });
    expect(result.deferred).toBe(false);
    expect(result.toolOfRecord).toBe("in-house");
    expect(result.findings.some((f) => f.pattern === "AWS_ACCESS_KEY_ID")).toBe(true);
  });

  it("falls back to in-house when the deferral throws", () => {
    writeAwsLeak();
    const throwingRunner: CommandRunner = () => {
      throw new Error("gitleaks blew up");
    };
    const result = scanSecrets(tmp, { probe: gitleaksPresent, runner: throwingRunner });
    expect(result.deferred).toBe(false);
    expect(result.toolOfRecord).toBe("in-house");
    expect(result.findings.length).toBeGreaterThan(0);
  });
});
