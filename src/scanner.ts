import * as vscode from "vscode";
import { RULES, Rule, Severity } from "./rules";
import { isManifest, scanDependencies } from "./dependencies";
import { collectSuppressions, isSuppressed } from "./suppressions";

export interface Finding {
  rule: Rule;
  range: vscode.Range;
  uri: vscode.Uri;
  lineText: string;
}

const SEVERITY_ORDER: Record<Severity, number> = {
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

const SEVERITY_WEIGHT: Record<Severity, number> = {
  low: 3,
  medium: 8,
  high: 16,
  critical: 28,
};

export function severityToVsCode(s: Severity): vscode.DiagnosticSeverity {
  switch (s) {
    case "critical":
    case "high":
      return vscode.DiagnosticSeverity.Error;
    case "medium":
      return vscode.DiagnosticSeverity.Warning;
    case "low":
      return vscode.DiagnosticSeverity.Information;
  }
}

function ruleApplies(rule: Rule, document: vscode.TextDocument): boolean {
  if (rule.languages && !rule.languages.includes(document.languageId)) {
    return false;
  }
  if (rule.filePattern) {
    // Normalize to forward slashes so file patterns are cross-platform.
    const path = document.uri.path.replace(/\\/g, "/");
    if (!rule.filePattern.test(path)) {
      return false;
    }
  }
  return true;
}

/** Scan a single document and return findings at/above the minimum severity. */
export function scanDocument(
  document: vscode.TextDocument,
  minSeverity: Severity = "low"
): Finding[] {
  const text = document.getText();
  const findings: Finding[] = [];
  const minOrder = SEVERITY_ORDER[minSeverity];
  const suppressions = collectSuppressions(text);

  for (const rule of RULES) {
    if (SEVERITY_ORDER[rule.severity] < minOrder) {
      continue;
    }
    if (!ruleApplies(rule, document)) {
      continue;
    }

    const flags = rule.pattern.flags.includes("g")
      ? rule.pattern.flags
      : rule.pattern.flags + "g";
    const re = new RegExp(rule.pattern.source, flags);

    let match: RegExpExecArray | null;
    while ((match = re.exec(text)) !== null) {
      const start = document.positionAt(match.index);
      const end = document.positionAt(match.index + match[0].length);
      const range = new vscode.Range(start, end);
      if (!isSuppressed(suppressions, rule, start.line)) {
        findings.push({
          rule,
          range,
          uri: document.uri,
          lineText: document.lineAt(start.line).text.trim(),
        });
      }
      // Guard against zero-width matches looping forever.
      if (match.index === re.lastIndex) {
        re.lastIndex++;
      }
    }
  }

  // Dependency Diff Security Watcher: for manifest/lock files, layer in
  // typosquat / known-incident / install-script findings alongside the rules.
  if (isManifest(document)) {
    for (const f of scanDependencies(document)) {
      if (
        SEVERITY_ORDER[f.rule.severity] >= minOrder &&
        !isSuppressed(suppressions, f.rule, f.range.start.line)
      ) {
        findings.push(f);
      }
    }
  }

  return findings;
}

export function findingToDiagnostic(finding: Finding): vscode.Diagnostic {
  const { rule } = finding;
  const diag = new vscode.Diagnostic(
    finding.range,
    `${rule.title}: ${rule.message}\nFix: ${rule.fix}`,
    severityToVsCode(rule.severity)
  );
  diag.source = "Risk Firewall";
  diag.code = `${rule.severity.toUpperCase()} · ${rule.id}`;
  return diag;
}

/**
 * Risk score 0–100. Higher = riskier. Uses diminishing returns so a file with
 * many low findings can't outscore one with a critical.
 */
export function riskScore(findings: Finding[]): number {
  if (findings.length === 0) {
    return 0;
  }
  const raw = findings.reduce(
    (sum, f) => sum + SEVERITY_WEIGHT[f.rule.severity],
    0
  );
  // Soft cap so the score approaches but never exceeds 100.
  return Math.min(100, Math.round(100 * (1 - Math.exp(-raw / 60))));
}

export function countBySeverity(
  findings: Finding[]
): Record<Severity, number> {
  const counts: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  };
  for (const f of findings) {
    counts[f.rule.severity]++;
  }
  return counts;
}
