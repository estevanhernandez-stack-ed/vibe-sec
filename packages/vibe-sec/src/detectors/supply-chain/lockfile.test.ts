import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  readLockfile,
  readDeclaredDeps,
  classifyPin,
  detectLockfile,
} from "./lockfile.js";

let tmp: string;
beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "vibe-sec-lockfile-"));
});
afterEach(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

function write(rel: string, content: string): void {
  fs.writeFileSync(path.join(tmp, rel), content, "utf8");
}

describe("classifyPin", () => {
  it("classifies floating, exact, caret, tilde, range, url", () => {
    expect(classifyPin("latest")).toBe("floating");
    expect(classifyPin("*")).toBe("floating");
    expect(classifyPin("1.2.x")).toBe("floating");
    expect(classifyPin("1.2.3")).toBe("exact");
    expect(classifyPin("^1.2.3")).toBe("caret");
    expect(classifyPin("~1.2.3")).toBe("tilde");
    expect(classifyPin(">=1.0.0 <2.0.0")).toBe("range");
    expect(classifyPin("github:user/repo")).toBe("url");
  });
});

describe("detectLockfile precedence", () => {
  it("detects npm package-lock.json", () => {
    write("package-lock.json", "{}");
    const d = detectLockfile(tmp);
    expect(d?.manager).toBe("npm");
  });

  it("detects pnpm-lock.yaml", () => {
    write("pnpm-lock.yaml", "lockfileVersion: '9.0'\n");
    expect(detectLockfile(tmp)?.manager).toBe("pnpm");
  });

  it("flags bun.lockb as binary, presence-only", () => {
    write("bun.lockb", "binarycontent");
    const info = readLockfile(tmp);
    expect(info.manager).toBe("bun");
    expect(info.binary).toBe(true);
    expect(info.hasIntegrity).toBe(true); // bun is integrity-bearing by design
  });
});

describe("readLockfile — npm package-lock v3", () => {
  it("parses packages map into entries with integrity flags", () => {
    write(
      "package-lock.json",
      JSON.stringify({
        name: "x",
        lockfileVersion: 3,
        packages: {
          "": { name: "x", version: "1.0.0" },
          "node_modules/lodash": {
            version: "4.17.21",
            integrity: "sha512-abc",
          },
          "node_modules/typescript": {
            version: "5.4.0",
            integrity: "sha512-def",
            dev: true,
          },
        },
      }),
    );
    const info = readLockfile(tmp);
    expect(info.manager).toBe("npm");
    expect(info.hasIntegrity).toBe(true);
    const lodash = info.entries.find((e) => e.name === "lodash");
    expect(lodash?.version).toBe("4.17.21");
    expect(lodash?.hasIntegrity).toBe(true);
    const ts = info.entries.find((e) => e.name === "typescript");
    expect(ts?.dev).toBe(true);
  });
});

describe("readDeclaredDeps — pin styles from package.json", () => {
  it("reads prod + dev deps and a floating pin is flaggable", () => {
    write(
      "package.json",
      JSON.stringify({
        dependencies: { express: "^4.18.0", chalk: "latest" },
        devDependencies: { vitest: "~1.6.0" },
      }),
    );
    const deps = readDeclaredDeps(tmp);
    const chalk = deps.find((d) => d.name === "chalk");
    expect(classifyPin(chalk!.range)).toBe("floating");
    const vitest = deps.find((d) => d.name === "vitest");
    expect(vitest?.dev).toBe(true);
  });
});
