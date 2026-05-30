// Agent Rules Generator. Emits a policy file (.cursorrules, .antigravityrules,
// CLAUDE.md, etc.) derived from the same RULES the scanner enforces, so an AI
// coding agent is instructed up-front to avoid the exact patterns this
// extension would otherwise flag. Content is written into a clearly delimited,
// regenerable block so re-running never clobbers a developer's own notes.

import * as vscode from "vscode";
import * as path from "path";
import { RULES, Rule, Category, Severity } from "./rules";

const BEGIN = "<!-- BEGIN AI Code Risk Firewall — auto-generated, edits inside are overwritten -->";
const END = "<!-- END AI Code Risk Firewall -->";

interface Target {
  label: string;
  file: string;
  detail: string;
}

const TARGETS: Target[] = [
  { label: ".cursorrules", file: ".cursorrules", detail: "Cursor AI rules" },
  { label: ".antigravityrules", file: ".antigravityrules", detail: "Antigravity agent rules" },
  { label: "CLAUDE.md", file: "CLAUDE.md", detail: "Claude Code custom instructions" },
  { label: "AGENTS.md", file: "AGENTS.md", detail: "Generic AGENTS.md instructions" },
  {
    label: ".github/copilot-instructions.md",
    file: ".github/copilot-instructions.md",
    detail: "GitHub Copilot instructions",
  },
];

const CATEGORY_TITLE: Record<Category, string> = {
  secret: "Secrets & credentials",
  auth: "Authentication & sessions",
  cors: "CORS",
  injection: "Injection (SQL / shell / code)",
  xss: "Cross-site scripting (XSS)",
  crypto: "Cryptography",
  network: "Network & TLS",
  config: "Configuration & logging",
  dependency: "Dependencies & supply chain",
};

const CATEGORY_ORDER: Category[] = [
  "secret",
  "auth",
  "injection",
  "xss",
  "cors",
  "crypto",
  "network",
  "config",
  "dependency",
];

const SEVERITY_RANK: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
};

/** Best-effort stack detection so the preamble reflects the actual repo. */
async function detectStack(root: vscode.Uri): Promise<string[]> {
  const stack: string[] = [];
  const has = async (rel: string): Promise<boolean> => {
    try {
      await vscode.workspace.fs.stat(vscode.Uri.joinPath(root, rel));
      return true;
    } catch {
      return false;
    }
  };
  if (await has("package.json")) stack.push("Node.js / JavaScript / TypeScript");
  if ((await has("requirements.txt")) || (await has("pyproject.toml"))) stack.push("Python");
  if (await has("next.config.js") || (await has("next.config.mjs"))) stack.push("Next.js");
  if (await has("go.mod")) stack.push("Go");
  if (await has("Gemfile")) stack.push("Ruby");
  if (await has("composer.json")) stack.push("PHP");
  if (await has("Cargo.toml")) stack.push("Rust");
  return stack;
}

/** Build the managed instruction block from the live rule set. */
function buildBlock(stack: string[]): string {
  const byCategory = new Map<Category, Rule[]>();
  for (const rule of RULES) {
    const list = byCategory.get(rule.category) ?? [];
    list.push(rule);
    byCategory.set(rule.category, list);
  }
  // Dependency rules are generated dynamically by the scanner, so describe the
  // policy explicitly rather than reading from RULES.
  byCategory.set("dependency", []);

  const lines: string[] = [];
  lines.push(BEGIN);
  lines.push("");
  lines.push("# AI Coding Agent Security Rules");
  lines.push("");
  lines.push(
    "These rules are generated from the AI Code Risk Firewall rule set. When writing or editing code in this repository, you MUST follow them. They exist to prevent the most common security mistakes in AI-generated code."
  );
  if (stack.length) {
    lines.push("");
    lines.push(`Detected stack: ${stack.join(", ")}.`);
  }
  lines.push("");
  lines.push("## Hard rules — never violate");
  lines.push("");
  lines.push("- Never hardcode secrets, API keys, tokens, passwords, or private keys. Read them from environment variables or a secrets manager.");
  lines.push("- Never use wildcard (`*`) CORS origins, especially with credentials enabled. Use an explicit allowlist.");
  lines.push("- Never build SQL, shell, or HTML by string concatenation/interpolation of untrusted input. Use parameterized queries, argument arrays, and escaping/sanitization.");
  lines.push("- Never disable TLS certificate verification (`rejectUnauthorized: false`, `verify=False`, `NODE_TLS_REJECT_UNAUTHORIZED=0`).");
  lines.push("- Never store auth tokens in `localStorage`; use httpOnly, Secure cookies.");
  lines.push("- Never add a dependency without confirming the exact name (watch for typosquats) and reviewing any install scripts.");
  lines.push("");

  for (const category of CATEGORY_ORDER) {
    const rules = byCategory.get(category);
    if (category !== "dependency" && (!rules || rules.length === 0)) {
      continue;
    }
    lines.push(`## ${CATEGORY_TITLE[category]}`);
    lines.push("");

    if (category === "dependency") {
      lines.push("- Do not introduce packages that are one character off a popular package name (typosquatting).");
      lines.push("- Do not add packages tied to known supply-chain incidents without verifying the version is unaffected.");
      lines.push("- Avoid packages with `preinstall`/`install`/`postinstall` scripts that run network, shell, `eval`, or `base64` commands. Prefer `--ignore-scripts` in CI.");
      lines.push("");
      continue;
    }

    const sorted = [...rules!].sort(
      (a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity]
    );
    const seen = new Set<string>();
    for (const r of sorted) {
      // Collapse near-duplicate fixes across language variants of one rule.
      const key = r.title + "|" + r.fix;
      if (seen.has(key)) {
        continue;
      }
      seen.add(key);
      lines.push(`- **${r.title}** (${r.severity}): ${r.fix}`);
    }
    lines.push("");
  }

  lines.push("When unsure whether something is safe, choose the more secure option and leave a comment explaining the tradeoff.");
  lines.push("");
  lines.push(END);
  return lines.join("\n");
}

/** Replace an existing managed block, or append one, preserving other content. */
function mergeIntoExisting(existing: string, block: string): string {
  const beginIdx = existing.indexOf(BEGIN);
  const endIdx = existing.indexOf(END);
  if (beginIdx !== -1 && endIdx !== -1 && endIdx > beginIdx) {
    const before = existing.slice(0, beginIdx);
    const after = existing.slice(endIdx + END.length);
    return (before.trimEnd() + "\n\n" + block + "\n" + after.trimStart()).trimEnd() + "\n";
  }
  const sep = existing.trim() === "" ? "" : existing.trimEnd() + "\n\n";
  return sep + block + "\n";
}

export async function generateAgentRules(): Promise<void> {
  const folder = vscode.workspace.workspaceFolders?.[0];
  if (!folder) {
    vscode.window.showWarningMessage(
      "Risk Firewall: open a folder/workspace before generating agent rules."
    );
    return;
  }

  const picks = await vscode.window.showQuickPick(
    TARGETS.map((t) => ({ label: t.label, detail: t.detail, picked: t.file === "CLAUDE.md" })),
    {
      canPickMany: true,
      title: "Generate Agent Security Rules",
      placeHolder: "Select which agent instruction file(s) to generate",
    }
  );
  if (!picks || picks.length === 0) {
    return;
  }

  const stack = await detectStack(folder.uri);
  const block = buildBlock(stack);
  const written: string[] = [];

  for (const pick of picks) {
    const target = TARGETS.find((t) => t.label === pick.label);
    if (!target) {
      continue;
    }
    const fileUri = vscode.Uri.joinPath(folder.uri, ...target.file.split("/"));

    let content: string;
    try {
      const raw = await vscode.workspace.fs.readFile(fileUri);
      content = mergeIntoExisting(Buffer.from(raw).toString("utf8"), block);
    } catch {
      content = block + "\n";
    }

    // Ensure parent dir exists (e.g. .github/).
    const dir = path.posix.dirname(target.file);
    if (dir && dir !== ".") {
      await vscode.workspace.fs.createDirectory(
        vscode.Uri.joinPath(folder.uri, ...dir.split("/"))
      );
    }
    await vscode.workspace.fs.writeFile(fileUri, Buffer.from(content, "utf8"));
    written.push(target.file);
  }

  const choice = await vscode.window.showInformationMessage(
    `Risk Firewall: wrote agent rules to ${written.join(", ")}.`,
    "Open"
  );
  if (choice === "Open" && written.length) {
    const doc = await vscode.workspace.openTextDocument(
      vscode.Uri.joinPath(folder.uri, ...written[0].split("/"))
    );
    await vscode.window.showTextDocument(doc);
  }
}
