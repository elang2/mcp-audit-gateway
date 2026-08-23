#!/usr/bin/env node
import { spawnSync } from "child_process";
import { fileURLToPath } from "url";
import { dirname, join } from "path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const vectorsDir = join(__dirname, "..", "test", "vectors");
const script = join(vectorsDir, "cross-sdk-diff.sh");

const args = process.argv.slice(2);
const jsonMode = args.includes("--json");
const helpMode = args.includes("--help") || args.includes("-h");

if (helpMode) {
  console.log(`mcp-diff — Cross-SDK differential testing for MCP

Usage:
  mcp-diff           Run tests, print human-readable output
  mcp-diff --json    Output structured JSON results
  mcp-diff --matrix  Generate markdown results matrix
  mcp-diff --help    Show this help

Detects installed language runtimes and runs serialization tests
across all available languages. Reports where outputs diverge.

Exit code = number of divergences (0 means all agree, capped at 125).

Languages tested (when available):
  JavaScript (node), Python (python3), Ruby (ruby), Go (go),
  Swift (swift), Java (javac), Perl (perl), PHP (php),
  Rust (rustc), Kotlin (kotlinc), C# (dotnet-script)
`);
  process.exit(0);
}

const matrixMode = args.includes("--matrix");

try {
  const targetScript = matrixMode
    ? join(vectorsDir, "generate-matrix.sh")
    : script;
  const scriptArgs = (!matrixMode && jsonMode) ? ["--json"] : [];

  const result = spawnSync("bash", [targetScript, ...scriptArgs], {
    cwd: vectorsDir,
    stdio: ["inherit", "pipe", "pipe"],
    encoding: "utf-8",
  });

  if (result.stdout) process.stdout.write(result.stdout);
  if (result.stderr) process.stderr.write(result.stderr);
  process.exit(result.status ?? 0);
} catch (e) {
  console.error(`Error: ${e.message}`);
  process.exit(1);
}
