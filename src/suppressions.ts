// Inline suppression support. A security linter that can't be silenced on a
// false positive gets disabled wholesale — so the firewall honors developer
// directives written as ordinary comments. Detection is purely textual and
// works in any language; the comment marker just has to appear on the line.
//
// Supported directives (a rule id/category list is optional; omit it to
// suppress every rule):
//
//   risk-firewall-ignore-line        secret/aws-access-key
//   risk-firewall-ignore-next-line   secret, cors
//   risk-firewall-ignore-file
//
// `risk-firewall-ignore` on its own is treated as `-line`.

import * as vscode from "vscode";
import { Rule } from "./rules";

export type SuppressionKind = "line" | "next-line" | "file";

export interface SuppressionState {
  /** Rule tokens suppressed for the whole file ("*" = everything). */
  file: Set<string>;
  /** Per-line-number rule tokens ("*" = everything on that line). */
  lines: Map<number, Set<string>>;
}

const DIRECTIVE =
  /risk-firewall-ignore(-next-line|-line|-file)?\b[ \t:=-]*([A-Za-z0-9 ,/_-]*)/g;

/** Line-comment prefix for a VS Code language id, used when inserting directives. */
export function commentPrefix(languageId: string): string {
  switch (languageId) {
    case "python":
    case "ruby":
    case "shellscript":
    case "powershell":
    case "yaml":
    case "dockerfile":
    case "makefile":
    case "perl":
    case "r":
    case "toml":
    case "properties":
    case "ini":
    case "terraform":
    case "dotenv":
      return "#";
    case "sql":
    case "lua":
    case "haskell":
      return "--";
    case "clojure":
    case "lisp":
      return ";;";
    default:
      // C-family: js/ts/tsx/jsx/go/php/java/c#/rust/c/c++/swift/kotlin/scala/...
      return "//";
  }
}

/** Parse the comma/space separated rule tokens after a directive. */
function parseTokens(raw: string): Set<string> {
  const tokens = raw
    .split(/[\s,]+/)
    .map((t) => t.trim())
    .filter(Boolean);
  // No explicit rule list means "suppress everything here".
  return tokens.length ? new Set(tokens) : new Set(["*"]);
}

/** Scan a document's text once and collect all suppression directives. */
export function collectSuppressions(text: string): SuppressionState {
  const state: SuppressionState = { file: new Set(), lines: new Map() };
  const lines = text.split(/\r\n|\r|\n/);

  lines.forEach((lineText, lineNo) => {
    DIRECTIVE.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = DIRECTIVE.exec(lineText)) !== null) {
      const kind: SuppressionKind =
        m[1] === "-file"
          ? "file"
          : m[1] === "-next-line"
          ? "next-line"
          : "line";
      const tokens = parseTokens(m[2] ?? "");

      if (kind === "file") {
        tokens.forEach((t) => state.file.add(t));
        continue;
      }
      const target = kind === "next-line" ? lineNo + 1 : lineNo;
      const set = state.lines.get(target) ?? new Set<string>();
      tokens.forEach((t) => set.add(t));
      state.lines.set(target, set);
    }
  });

  return state;
}

/** Does a token set match this rule? "*" matches all; id and category match too. */
function tokenMatches(tokens: Set<string>, rule: Rule): boolean {
  return (
    tokens.has("*") ||
    tokens.has(rule.id) ||
    tokens.has(rule.category) ||
    // Allow a bare rule name without the "category/" prefix.
    tokens.has(rule.id.split("/").pop() ?? rule.id)
  );
}

/** Is a finding for `rule` on zero-based `line` suppressed by a directive? */
export function isSuppressed(
  state: SuppressionState,
  rule: Rule,
  line: number
): boolean {
  if (state.file.size && tokenMatches(state.file, rule)) {
    return true;
  }
  const lineTokens = state.lines.get(line);
  return !!lineTokens && tokenMatches(lineTokens, rule);
}
