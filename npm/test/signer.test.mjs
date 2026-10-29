// Tests for the npm packaging of the signer (REF-553): node --test npm/test/*.test.mjs
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const repo = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const stage = join(repo, "scripts", "npm-stage.mjs");
const platforms = JSON.parse(readFileSync(join(repo, "npm", "signer", "platforms.json"), "utf8"));

// fakeDist writes one stand-in binary per platform plus a matching SHA256SUMS. The linux-x64 one is a
// shell script that echoes its arguments and exits 7, so the shim can be run end to end.
function fakeDist(tag) {
  const dir = mkdtempSync(join(tmpdir(), "npm-stage-dist-"));
  const lines = [];
  for (const p of Object.values(platforms)) {
    const asset = `opensouk-signer_${tag}_${p.goos}_${p.goarch}${p.exe.endsWith(".exe") ? ".exe" : ""}`;
    const body = `#!/bin/sh\necho "${p.goos}/${p.goarch} $*"\nexit 7\n`;
    writeFileSync(join(dir, asset), body);
    lines.push(`${createHash("sha256").update(body).digest("hex")}  ${asset}`);
  }
  writeFileSync(join(dir, "SHA256SUMS"), lines.join("\n") + "\n");
  return dir;
}

function runStage(...args) {
  return spawnSync(process.execPath, [stage, ...args], { encoding: "utf8" });
}

test("stage pins every package to the tag and copies the release bytes", () => {
  const dist = fakeDist("v1.2.3");
  const out = join(mkdtempSync(join(tmpdir(), "npm-stage-out-")), "pkgs");
  const r = runStage("v1.2.3", dist, out);
  assert.equal(r.status, 0, r.stderr);

  const main = JSON.parse(readFileSync(join(out, "signer", "package.json"), "utf8"));
  assert.equal(main.version, "1.2.3");
  const license = readFileSync(join(repo, "LICENSE"), "utf8");
  for (const dir of ["signer", ...Object.keys(platforms).map((k) => `signer-${k}`)]) {
    assert.equal(JSON.parse(readFileSync(join(out, dir, "package.json"), "utf8")).license, "MIT", dir);
    assert.equal(readFileSync(join(out, dir, "LICENSE"), "utf8"), license, dir);
  }
  assert.deepEqual(
    main.optionalDependencies,
    Object.fromEntries(Object.keys(platforms).map((k) => [`@opensouk/signer-${k}`, "1.2.3"])),
  );
  for (const [key, p] of Object.entries(platforms)) {
    const pkg = JSON.parse(readFileSync(join(out, `signer-${key}`, "package.json"), "utf8"));
    assert.equal(pkg.version, "1.2.3");
    assert.deepEqual([pkg.os, pkg.cpu], [[p.os], [p.cpu]]);
    assert.equal(pkg.repository.url, main.repository.url);
    const asset = `opensouk-signer_v1.2.3_${p.goos}_${p.goarch}${p.exe.endsWith(".exe") ? ".exe" : ""}`;
    assert.deepEqual(readFileSync(join(out, `signer-${key}`, "bin", p.exe)), readFileSync(join(dist, asset)));
  }
});

test("stage refuses a binary that does not match SHA256SUMS", () => {
  const dist = fakeDist("v1.2.3");
  writeFileSync(join(dist, "opensouk-signer_v1.2.3_darwin_arm64"), "tampered");
  const r = runStage("v1.2.3", dist, join(dist, "out"));
  assert.equal(r.status, 1);
  assert.match(r.stderr, /opensouk-signer_v1\.2\.3_darwin_arm64: sha256 [0-9a-f]{64}, SHA256SUMS says/);
});

test("stage refuses a binary SHA256SUMS does not list", () => {
  const dist = fakeDist("v1.2.3");
  const sums = readFileSync(join(dist, "SHA256SUMS"), "utf8").split("\n").filter((l) => !l.includes("windows"));
  writeFileSync(join(dist, "SHA256SUMS"), sums.join("\n"));
  const r = runStage("v1.2.3", dist, join(dist, "out"));
  assert.equal(r.status, 1);
  assert.match(r.stderr, /SHA256SUMS has no entry for opensouk-signer_v1\.2\.3_windows_amd64\.exe/);
});

test("stage refuses a version that is not vX.Y.Z", () => {
  for (const tag of ["1.2.3", "v1.2", "v1.2.3-rc1", "latest"]) {
    const r = runStage(tag, "/nonexistent", "/nonexistent");
    assert.equal(r.status, 1, tag);
    assert.match(r.stderr, /version must look like v1\.2\.3/, tag);
  }
});

// installLayout stages the packages into node_modules/@opensouk/, the way npm installs them on a
// linux-x64 host, and returns the path of the shim there.
function installLayout() {
  const dist = fakeDist("v1.2.3");
  const out = join(dist, "out");
  assert.equal(runStage("v1.2.3", dist, out).status, 0);
  const nm = join(mkdtempSync(join(tmpdir(), "npm-layout-")), "node_modules", "@opensouk");
  mkdirSync(nm, { recursive: true });
  cpSync(join(out, "signer"), join(nm, "signer"), { recursive: true });
  cpSync(join(out, "signer-linux-x64"), join(nm, "signer-linux-x64"), { recursive: true });
  return join(nm, "signer", "bin", "opensouk-signer.js");
}

test("shim resolves the installed platform package and explains the missing ones", () => {
  const shim = installLayout();
  const { binaryPath } = createRequire(import.meta.url)(shim);
  assert.equal(
    binaryPath("linux", "x64"),
    join(dirname(shim), "..", "..", "signer-linux-x64", "bin", "opensouk-signer"),
  );
  assert.throws(() => binaryPath("darwin", "arm64"), /@opensouk\/signer-darwin-arm64 is not installed/);
  assert.throws(() => binaryPath("sunos", "x64"), /no opensouk-signer build for sunos-x64; supported: linux-x64, /);
});

test("shim passes arguments, stdout and the exit code through", { skip: process.platform !== "linux" || process.arch !== "x64" }, () => {
  const shim = installLayout();
  const r = spawnSync(process.execPath, [shim, "--version", "a b"], { encoding: "utf8" });
  assert.equal(r.stdout, "linux/amd64 --version a b\n");
  assert.equal(r.stderr, "");
  assert.equal(r.status, 7);
});

test("the shim's published files include everything it requires", () => {
  const pkg = JSON.parse(readFileSync(join(repo, "npm", "signer", "package.json"), "utf8"));
  const shimSrc = readFileSync(join(repo, "npm", "signer", "bin", "opensouk-signer.js"), "utf8");
  for (const m of shimSrc.matchAll(/require\("\.\.\/([^"]+)"\)/g)) assert.ok(pkg.files.includes(m[1]), m[1]);
  assert.ok(pkg.files.includes(pkg.bin["opensouk-signer"]));
  // npm keeps the mode from the tarball; stage sets it too, but a tracked 755 keeps local packs runnable.
  const mode = execFileSync("git", ["-C", repo, "ls-files", "-s", "npm/signer/bin/opensouk-signer.js"], { encoding: "utf8" });
  assert.match(mode, /^100755 /);
});
