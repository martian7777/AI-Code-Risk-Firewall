// Quick Fixes for Risk Firewall diagnostics. Findings on their own are just
// red squiggles; these lightbulb actions make them actionable — silence a
// false positive inline, mute a noisy rule for the whole file, or jump to the
// suggested fix. The suppression comments written here are the same ones the
// scanner reads back in (see suppressions.ts).

import * as vscode from "vscode";
import { commentPrefix } from "./suppressions";

const SOURCE = "Risk Firewall";

/** Pull the rule id out of a diagnostic code like "HIGH · injection/eval". */
function ruleIdOf(diag: vscode.Diagnostic): string | undefined {
  const code = typeof diag.code === "string" ? diag.code : String(diag.code ?? "");
  const parts = code.split("·");
  return parts.length > 1 ? parts[parts.length - 1].trim() : undefined;
}

/** Leading whitespace of a line, so inserted comments line up with the code. */
function indentOf(document: vscode.TextDocument, line: number): string {
  const text = document.lineAt(line).text;
  return text.slice(0, text.length - text.trimStart().length);
}

function insertAction(
  title: string,
  document: vscode.TextDocument,
  line: number,
  comment: string,
  diag: vscode.Diagnostic
): vscode.CodeAction {
  const action = new vscode.CodeAction(title, vscode.CodeActionKind.QuickFix);
  const indent = indentOf(document, line);
  const edit = new vscode.WorkspaceEdit();
  edit.insert(
    document.uri,
    new vscode.Position(line, 0),
    `${indent}${comment}\n`
  );
  action.edit = edit;
  action.diagnostics = [diag];
  return action;
}

export class RiskFirewallCodeActions implements vscode.CodeActionProvider {
  static readonly providedKinds = [vscode.CodeActionKind.QuickFix];

  provideCodeActions(
    document: vscode.TextDocument,
    _range: vscode.Range | vscode.Selection,
    context: vscode.CodeActionContext
  ): vscode.CodeAction[] {
    const ours = context.diagnostics.filter((d) => d.source === SOURCE);
    if (ours.length === 0) {
      return [];
    }

    const prefix = commentPrefix(document.languageId);
    const actions: vscode.CodeAction[] = [];

    for (const diag of ours) {
      const ruleId = ruleIdOf(diag);
      const line = diag.range.start.line;

      // 1. Silence just this finding, on this line.
      if (ruleId) {
        actions.push(
          insertAction(
            `Risk Firewall: ignore "${ruleId}" on this line`,
            document,
            line,
            `${prefix} risk-firewall-ignore-next-line ${ruleId}`,
            diag
          )
        );
      }

      // 2. Silence this rule across the whole file.
      if (ruleId) {
        const fileAction = insertAction(
          `Risk Firewall: ignore "${ruleId}" in this file`,
          document,
          0,
          `${prefix} risk-firewall-ignore-file ${ruleId}`,
          diag
        );
        actions.push(fileAction);
      }

      // 3. Silence every firewall finding on this line (escape hatch).
      actions.push(
        insertAction(
          "Risk Firewall: ignore all findings on this line",
          document,
          line,
          `${prefix} risk-firewall-ignore-next-line`,
          diag
        )
      );

      // 4. Open the report for the broader picture.
      const report = new vscode.CodeAction(
        "Risk Firewall: show full risk report",
        vscode.CodeActionKind.QuickFix
      );
      report.command = {
        command: "aiRiskFirewall.showReport",
        title: "Show Risk Report",
      };
      report.diagnostics = [diag];
      actions.push(report);
    }

    return actions;
  }
}
