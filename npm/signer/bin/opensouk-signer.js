#!/usr/bin/env node
// Runs the opensouk-signer binary from the platform package npm installed next to this one.
// stdout belongs to the MCP protocol: this file writes only to stderr.
"use strict";

const { spawn } = require("node:child_process");
const path = require("node:path");
const platforms = require("../platforms.json");

function binaryPath(platform, arch) {
  const key = `${platform}-${arch}`;
  const target = platforms[key];
  if (!target) {
    throw new Error(
      `no opensouk-signer build for ${key}; supported: ${Object.keys(platforms).join(", ")}`,
    );
  }
  const pkg = `@opensouk/signer-${key}`;
  let dir;
  try {
    dir = path.dirname(require.resolve(`${pkg}/package.json`));
  } catch {
    throw new Error(
      `${pkg} is not installed. npm skips it when optional dependencies are disabled ` +
        "(--omit=optional, --no-optional): reinstall without that flag",
    );
  }
  return path.join(dir, "bin", target.exe);
}

function main() {
  let bin;
  try {
    bin = binaryPath(process.platform, process.arch);
  } catch (err) {
    process.stderr.write(`opensouk-signer: ${err.message}\n`);
    process.exit(1);
  }
  const child = spawn(bin, process.argv.slice(2), { stdio: "inherit" });
  const forward = (sig) => () => child.kill(sig);
  for (const sig of ["SIGINT", "SIGTERM", "SIGHUP"]) process.on(sig, forward(sig));
  child.on("error", (err) => {
    process.stderr.write(`opensouk-signer: cannot run ${bin}: ${err.message}\n`);
    process.exit(1);
  });
  child.on("exit", (code, signal) => {
    if (signal) {
      process.removeAllListeners(signal);
      process.kill(process.pid, signal);
      return;
    }
    process.exit(code ?? 1);
  });
}

if (require.main === module) main();

module.exports = { binaryPath };
