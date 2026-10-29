#!/usr/bin/env node
// Stages the npm packages for one signer release (REF-553).
//
//   node scripts/npm-stage.mjs <vX.Y.Z> <dist-dir> <out-dir>
//
// <dist-dir> holds the release assets: opensouk-signer_<tag>_<goos>_<goarch>[.exe] and SHA256SUMS.
// Writes <out-dir>/signer-<platform>/ for each platform and <out-dir>/signer/, with every version
// pinned to the tag. Refuses a binary whose sha256 is not the one SHA256SUMS lists, so the npm
// packages carry exactly the bytes of the GitHub release.
import { createHash } from "node:crypto";
import { chmodSync, cpSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const repoDir = join(dirname(fileURLToPath(import.meta.url)), "..");
const srcDir = join(repoDir, "npm", "signer");

function fail(msg) {
  process.stderr.write(`npm-stage: ${msg}\n`);
  process.exit(1);
}

const [tag, dist, out] = process.argv.slice(2);
if (!tag || !dist || !out) fail("usage: npm-stage.mjs <vX.Y.Z> <dist-dir> <out-dir>");
if (!/^v\d+\.\d+\.\d+$/.test(tag)) fail(`version must look like v1.2.3 (got ${tag})`);
const version = tag.slice(1);

const sums = new Map();
for (const line of readFileSync(join(dist, "SHA256SUMS"), "utf8").split("\n")) {
  const m = line.match(/^([0-9a-f]{64}) [ *](\S+)$/);
  if (m) sums.set(m[2], m[1]);
}

const platforms = JSON.parse(readFileSync(join(srcDir, "platforms.json"), "utf8"));
const main = JSON.parse(readFileSync(join(srcDir, "package.json"), "utf8"));

rmSync(out, { recursive: true, force: true });
main.version = version;
main.optionalDependencies = {};

for (const [key, p] of Object.entries(platforms)) {
  const asset = `opensouk-signer_${tag}_${p.goos}_${p.goarch}${p.exe.endsWith(".exe") ? ".exe" : ""}`;
  const want = sums.get(asset);
  if (!want) fail(`SHA256SUMS has no entry for ${asset}`);
  const bytes = readFileSync(join(dist, asset));
  const got = createHash("sha256").update(bytes).digest("hex");
  if (got !== want) fail(`${asset}: sha256 ${got}, SHA256SUMS says ${want}`);

  const name = `@opensouk/signer-${key}`;
  const dir = join(out, `signer-${key}`);
  mkdirSync(join(dir, "bin"), { recursive: true });
  writeFileSync(join(dir, "bin", p.exe), bytes);
  chmodSync(join(dir, "bin", p.exe), 0o755);
  writeFileSync(
    join(dir, "package.json"),
    JSON.stringify(
      {
        name,
        version,
        description: `opensouk-signer ${tag} binary for ${key}; installed by @opensouk/signer`,
        license: main.license,
        repository: main.repository,
        os: [p.os],
        cpu: [p.cpu],
        files: [`bin/${p.exe}`, "LICENSE"],
        preferUnplugged: true,
      },
      null,
      2,
    ) + "\n",
  );
  cpSync(join(repoDir, "LICENSE"), join(dir, "LICENSE"));
  writeFileSync(join(dir, "README.md"), `# ${name}\n\nThe ${key} binary of [@opensouk/signer](https://www.npmjs.com/package/@opensouk/signer) ${tag}. Install that package, not this one.\n`);
  main.optionalDependencies[name] = version;
}

const mainDir = join(out, "signer");
mkdirSync(join(mainDir, "bin"), { recursive: true });
cpSync(join(srcDir, "bin", "opensouk-signer.js"), join(mainDir, "bin", "opensouk-signer.js"));
chmodSync(join(mainDir, "bin", "opensouk-signer.js"), 0o755);
cpSync(join(srcDir, "platforms.json"), join(mainDir, "platforms.json"));
cpSync(join(srcDir, "README.md"), join(mainDir, "README.md"));
cpSync(join(repoDir, "LICENSE"), join(mainDir, "LICENSE"));
writeFileSync(join(mainDir, "package.json"), JSON.stringify(main, null, 2) + "\n");

process.stdout.write(`staged @opensouk/signer ${version} + ${Object.keys(platforms).length} platform packages in ${out}\n`);
