import * as vscode from "vscode";
import { Finding, countBySeverity, riskScore } from "./scanner";
import { Severity } from "./rules";

let panel: vscode.WebviewPanel | undefined;

const SEVERITY_COLOR: Record<Severity, string> = {
  critical: "#ff5c5c",
  high: "#ff9f43",
  medium: "#ffd93d",
  low: "#5ca8ff",
};

const SEVERITY_RANK: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
};

export function showReport(
  context: vscode.ExtensionContext,
  findings: Finding[],
  scope: string
): void {
  if (!panel) {
    panel = vscode.window.createWebviewPanel(
      "aiRiskFirewallReport",
      "AI Risk Report",
      vscode.ViewColumn.Beside,
      { enableScripts: true, retainContextWhenHidden: true }
    );
    panel.onDidDispose(() => (panel = undefined), null, context.subscriptions);
    panel.webview.onDidReceiveMessage(async (msg) => {
      if (msg?.command === "open") {
        const uri = vscode.Uri.parse(msg.uri);
        const doc = await vscode.workspace.openTextDocument(uri);
        const editor = await vscode.window.showTextDocument(doc);
        const pos = new vscode.Position(msg.line, msg.character ?? 0);
        editor.selection = new vscode.Selection(pos, pos);
        editor.revealRange(
          new vscode.Range(pos, pos),
          vscode.TextEditorRevealType.InCenter
        );
      }
    });
  }
  panel.webview.html = renderHtml(findings, scope);
  panel.reveal(vscode.ViewColumn.Beside);
}

function esc(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function renderHtml(findings: Finding[], scope: string): string {
  const score = riskScore(findings);
  const counts = countBySeverity(findings);
  const sorted = [...findings].sort(
    (a, b) =>
      SEVERITY_RANK[a.rule.severity] - SEVERITY_RANK[b.rule.severity]
  );

  const scoreColor =
    score >= 70 ? "#ff5c5c" : score >= 35 ? "#ffd93d" : "#3ddc97";

  const rows = sorted
    .map((f) => {
      const ws = vscode.workspace.getWorkspaceFolder(f.uri);
      const rel = ws
        ? vscode.workspace.asRelativePath(f.uri)
        : f.uri.fsPath;
      const color = SEVERITY_COLOR[f.rule.severity];
      return `
      <tr class="row" data-uri="${esc(f.uri.toString())}" data-line="${
        f.range.start.line
      }" data-char="${f.range.start.character}">
        <td><span class="pill" style="background:${color}22;color:${color};border:1px solid ${color}55">${f.rule.severity.toUpperCase()}</span></td>
        <td><strong>${esc(f.rule.title)}</strong><div class="msg">${esc(
        f.rule.message
      )}</div><div class="fix">Fix: ${esc(f.rule.fix)}</div></td>
        <td class="loc">${esc(rel)}:${f.range.start.line + 1}<div class="code">${esc(
        f.lineText.slice(0, 100)
      )}</div></td>
      </tr>`;
    })
    .join("");

  const summary = (["critical", "high", "medium", "low"] as Severity[])
    .map((s) => {
      const c = SEVERITY_COLOR[s];
      return `<div class="stat"><div class="num" style="color:${c}">${counts[s]}</div><div class="lbl">${s}</div></div>`;
    })
    .join("");

  const empty = findings.length === 0;

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline';" />
<style>
  body { font-family: var(--vscode-font-family); color: var(--vscode-foreground); padding: 16px 20px; }
  h1 { font-size: 18px; margin: 0 0 2px; }
  .scope { opacity: .6; font-size: 12px; margin-bottom: 16px; }
  .top { display:flex; gap:24px; align-items:center; margin-bottom:20px; flex-wrap:wrap; }
  .gauge { font-size: 44px; font-weight: 800; line-height:1; }
  .gauge small { font-size:13px; font-weight:500; opacity:.6; display:block; }
  .stats { display:flex; gap:18px; }
  .stat { text-align:center; }
  .num { font-size: 24px; font-weight: 700; }
  .lbl { font-size: 11px; text-transform: uppercase; opacity:.6; }
  table { width:100%; border-collapse: collapse; }
  td { padding: 10px 8px; border-top: 1px solid var(--vscode-panel-border); vertical-align: top; font-size: 13px; }
  .row { cursor: pointer; }
  .row:hover { background: var(--vscode-list-hoverBackground); }
  .pill { padding: 2px 8px; border-radius: 10px; font-size: 11px; font-weight: 700; white-space:nowrap; }
  .msg { opacity: .8; margin-top: 3px; }
  .fix { opacity: .65; margin-top: 3px; font-style: italic; }
  .loc { font-family: var(--vscode-editor-font-family); opacity:.85; white-space:nowrap; }
  .code { font-family: var(--vscode-editor-font-family); opacity:.5; margin-top:4px; white-space:pre; overflow:hidden; }
  .empty { text-align:center; padding:60px 0; opacity:.6; }
</style>
</head>
<body>
  <h1>AI Code Risk Firewall</h1>
  <div class="scope">${esc(scope)}</div>
  ${
    empty
      ? `<div class="empty">✅ No risks detected at the current severity threshold.</div>`
      : `<div class="top">
          <div class="gauge" style="color:${scoreColor}">${score}<small>RISK SCORE / 100</small></div>
          <div class="stats">${summary}</div>
        </div>
        <table>
          <tbody>${rows}</tbody>
        </table>`
  }
  <script>
    const vscode = acquireVsCodeApi();
    document.querySelectorAll('.row').forEach(r => {
      r.addEventListener('click', () => {
        vscode.postMessage({
          command: 'open',
          uri: r.dataset.uri,
          line: Number(r.dataset.line),
          character: Number(r.dataset.char)
        });
      });
    });
  </script>
</body>
</html>`;
}
