// Dependency Diff Security Watcher. Inspects manifest/lock files (package.json,
// package-lock.json, yarn.lock, pnpm-lock.yaml) and flags risky dependencies as
// they appear: typosquats of popular packages, packages tied to known supply-
// chain incidents, and lifecycle install scripts that are a common malware
// vector. Detection is purely local — no registry calls — and produces the same
// Finding shape as the regex rules so it flows through diagnostics + the report.

import * as vscode from "vscode";
import { Rule, Severity } from "./rules";
import type { Finding } from "./scanner";

/** Manifest/lock files this watcher understands. */
const MANIFEST = /(^|\/)(package\.json|package-lock\.json|yarn\.lock|pnpm-lock\.yaml)$/i;

export function isManifest(document: vscode.TextDocument): boolean {
  return MANIFEST.test(document.uri.path.replace(/\\/g, "/"));
}

// A small, high-signal set of the most-depended-on npm packages. Typosquat
// detection compares new dependency names against these; the goal is to catch
// the classic "one keystroke off a household name" attack, not to be exhaustive.
const POPULAR_PACKAGES = [
  "react", "react-dom", "lodash", "express", "axios", "chalk", "commander",
  "moment", "request", "async", "debug", "vue", "webpack", "typescript",
  "eslint", "prettier", "jest", "mocha", "dotenv", "body-parser", "cors",
  "mongoose", "next", "redux", "rxjs", "underscore", "bluebird", "classnames",
  "uuid", "yargs", "glob", "fs-extra", "node-fetch", "socket.io", "ws",
  "jsonwebtoken", "bcrypt", "passport", "nodemon", "babel-core", "core-js",
  "tslib", "semver", "minimist", "colors", "inquirer", "ora", "dayjs",
];
const POPULAR_SET = new Set(POPULAR_PACKAGES);

// Packages tied to publicized supply-chain incidents (compromise, protestware,
// or deliberate sabotage). These names are not inherently malicious today, but
// their presence warrants a version/provenance check. Value = short reason.
const FLAGGED_PACKAGES: Record<string, string> = {
  "event-stream": "compromised in 2018 to steal bitcoin-wallet credentials (via flatmap-stream).",
  "flatmap-stream": "malicious payload injected into event-stream's dependency chain.",
  "eslint-scope": "a compromised release exfiltrated npm tokens in 2018.",
  "ua-parser-js": "hijacked releases in 2021 shipped a password stealer and crypto-miner.",
  "coa": "hijacked in 2021 to deliver malware to build pipelines.",
  "rc": "targeted by a 2021 hijack alongside coa.",
  "node-ipc": "shipped destructive 'protestware' that wiped files based on geolocation.",
  "colors": "author deliberately sabotaged it with an infinite loop in 2022.",
  "faker": "author deliberately zeroed out the package in 2022.",
  "getcookies": "used in a 2018 backdoor to read request cookies.",
};

/** Manifest keys that hold dependency maps. */
const DEP_SECTIONS = [
  "dependencies",
  "devDependencies",
  "peerDependencies",
  "optionalDependencies",
];

/** Lifecycle scripts that run automatically on install — prime malware vectors. */
const INSTALL_HOOKS = ["preinstall", "install", "postinstall"];

/** Levenshtein edit distance, capped early once it exceeds `max`. */
function editDistance(a: string, b: string, max: number): number {
  if (Math.abs(a.length - b.length) > max) {
    return max + 1;
  }
  let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    const curr = [i];
    let rowMin = i;
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      const v = Math.min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost);
      curr[j] = v;
      if (v < rowMin) {
        rowMin = v;
      }
    }
    if (rowMin > max) {
      return max + 1;
    }
    prev = curr;
  }
  return prev[b.length];
}

/** Nearest popular package within edit distance 1 (and not an exact match). */
function typosquatTarget(name: string): string | undefined {
  if (POPULAR_SET.has(name) || name.startsWith("@")) {
    return undefined;
  }
  // Ignore very short names — single-keystroke distance is meaningless there.
  if (name.length < 4) {
    return undefined;
  }
  for (const popular of POPULAR_PACKAGES) {
    if (editDistance(name, popular, 1) <= 1) {
      return popular;
    }
  }
  return undefined;
}

function makeRule(
  id: string,
  title: string,
  severity: Severity,
  message: string,
  fix: string
): Rule {
  return { id, title, category: "dependency", severity, pattern: /$^/, message, fix };
}

/** Build a Finding anchored at `index` (length `len`) within the document. */
function finding(
  document: vscode.TextDocument,
  index: number,
  len: number,
  rule: Rule
): Finding {
  const start = document.positionAt(index);
  const end = document.positionAt(index + len);
  return {
    rule,
    range: new vscode.Range(start, end),
    uri: document.uri,
    lineText: document.lineAt(start.line).text.trim(),
  };
}

/**
 * Locate the first occurrence of a quoted manifest key (e.g. a dependency name
 * or "postinstall") and return the index of the name inside the quotes.
 */
function locateKey(text: string, key: string, fromIndex = 0): number {
  const esc = key.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const re = new RegExp('"' + esc + '"\\s*:', "g");
  re.lastIndex = fromIndex;
  const m = re.exec(text);
  return m ? m.index + 1 : -1; // +1 to skip the opening quote
}

/**
 * Scan a manifest/lock document for risky dependencies. Returns findings at or
 * above `minSeverity` (ordering is applied by the caller via SEVERITY_ORDER, so
 * we return everything and let the caller filter — matching the rule engine).
 */
export function scanDependencies(document: vscode.TextDocument): Finding[] {
  const findings: Finding[] = [];
  const text = document.getText();
  const path = document.uri.path.replace(/\\/g, "/").toLowerCase();

  // JSON manifests (package.json, package-lock.json) parse cleanly. yarn.lock /
  // pnpm-lock.yaml don't, so fall back to extracting bare top-level names.
  const isJson = path.endsWith(".json");

  const names = new Set<string>();
  let scripts: Record<string, unknown> | undefined;

  if (isJson) {
    let parsed: any;
    try {
      parsed = JSON.parse(text);
    } catch {
      return findings; // Mid-edit / invalid JSON — skip silently.
    }
    for (const section of DEP_SECTIONS) {
      const deps = parsed?.[section];
      if (deps && typeof deps === "object") {
        for (const name of Object.keys(deps)) {
          names.add(name);
        }
      }
    }
    // package-lock.json v2/v3: dependency names live under "packages"/"dependencies".
    for (const lockSection of ["dependencies", "packages"]) {
      const block = parsed?.[lockSection];
      if (block && typeof block === "object") {
        for (const key of Object.keys(block)) {
          const name = key.replace(/^node_modules\//, "").split("/node_modules/").pop();
          if (name && name !== "") {
            names.add(name);
          }
        }
      }
    }
    if (parsed?.scripts && typeof parsed.scripts === "object") {
      scripts = parsed.scripts;
    }
  } else {
    // yarn.lock / pnpm-lock.yaml: pull names from "name@range" or "/name@range"
    // headers. Good enough to catch typosquats and flagged packages by name.
    const re = /(?:^|\n)["']?\/?(@?[a-z0-9][\w.-]*(?:\/[\w.-]+)?)@/gi;
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) {
      names.add(m[1]);
    }
  }

  // --- per-dependency checks: typosquat + known incidents
  for (const name of names) {
    const idx = locateKey(text, name);

    const flagged = FLAGGED_PACKAGES[name];
    if (flagged) {
      const rule = makeRule(
        "dependency/known-incident",
        `Package with known supply-chain incident: ${name}`,
        "high",
        `"${name}" has a documented supply-chain incident — ${flagged}`,
        "Verify the exact version is unaffected, pin it, and prefer a maintained alternative if available."
      );
      findings.push(finding(document, idx < 0 ? 0 : idx, name.length, rule));
      continue;
    }

    const target = typosquatTarget(name);
    if (target) {
      const rule = makeRule(
        "dependency/typosquat",
        `Possible typosquat of "${target}"`,
        "critical",
        `"${name}" is one character away from the popular package "${target}" — a classic typosquatting attack.`,
        `Confirm you meant "${name}" and not "${target}". Remove it if it was a mistake.`
      );
      findings.push(finding(document, idx < 0 ? 0 : idx, name.length, rule));
    }
  }

  // --- install-script hooks (package.json only)
  if (scripts) {
    for (const hook of INSTALL_HOOKS) {
      const body = scripts[hook];
      if (typeof body !== "string" || body.trim() === "") {
        continue;
      }
      const idx = locateKey(text, hook);
      const looksRisky =
        /\b(curl|wget|node\s+-e|eval|base64|child_process|powershell|bash\s+-c|sh\s+-c|chmod|\|\s*sh)\b/i.test(
          body
        );
      const rule = makeRule(
        "dependency/install-script",
        `Lifecycle install script: "${hook}"`,
        looksRisky ? "high" : "medium",
        looksRisky
          ? `The "${hook}" script runs automatically on install and contains shell/network/eval commands — a common malware vector: ${body.slice(0, 120)}`
          : `The "${hook}" script runs automatically on every install. Review what it executes: ${body.slice(0, 120)}`,
        "Audit the command. Prefer explicit build steps; run installs with --ignore-scripts in CI where possible."
      );
      findings.push(finding(document, idx < 0 ? 0 : idx, hook.length, rule));
    }
  }

  return findings;
}
