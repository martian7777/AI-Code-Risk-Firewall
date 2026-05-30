import * as vscode from "vscode";
import {
  scanDocument,
  findingToDiagnostic,
  riskScore,
  Finding,
} from "./scanner";
import { Severity } from "./rules";
import { showReport } from "./report";
import { isManifest } from "./dependencies";
import { generateAgentRules } from "./agentRules";

let diagnostics: vscode.DiagnosticCollection;
let statusBar: vscode.StatusBarItem;
const debounceTimers = new Map<string, NodeJS.Timeout>();

// File types worth scanning. Keeps workspace scans fast and avoids binaries.
const SCANNABLE = /\.(js|jsx|ts|tsx|mjs|cjs|py|env|json|yml|yaml|tf|rb|go|php|java|cs|vue|svelte|astro|md|txt|sh|ps1)$/i;

function config() {
  return vscode.workspace.getConfiguration("aiRiskFirewall");
}

function minSeverity(): Severity {
  return config().get<Severity>("minimumSeverity", "low");
}

function isScannable(document: vscode.TextDocument): boolean {
  if (document.uri.scheme !== "file") {
    return false;
  }
  // Lock files like yarn.lock have no scannable extension but are watched by the
  // Dependency Diff Security Watcher, so allow them through explicitly.
  return SCANNABLE.test(document.uri.fsPath) || isManifest(document);
}

function scanAndReport(document: vscode.TextDocument): Finding[] {
  if (!config().get<boolean>("enable", true) || !isScannable(document)) {
    diagnostics.delete(document.uri);
    return [];
  }
  const findings = scanDocument(document, minSeverity());
  diagnostics.set(document.uri, findings.map(findingToDiagnostic));
  return findings;
}

function updateStatusBar(findings: Finding[]): void {
  const score = riskScore(findings);
  if (findings.length === 0) {
    statusBar.text = "$(shield) Risk 0";
    statusBar.backgroundColor = undefined;
    statusBar.tooltip = "AI Code Risk Firewall: no risks in this file";
  } else {
    const icon = score >= 70 ? "$(alert)" : "$(shield)";
    statusBar.text = `${icon} Risk ${score}`;
    statusBar.backgroundColor =
      score >= 70
        ? new vscode.ThemeColor("statusBarItem.errorBackground")
        : score >= 35
        ? new vscode.ThemeColor("statusBarItem.warningBackground")
        : undefined;
    statusBar.tooltip = `AI Code Risk Firewall: ${findings.length} finding(s), risk ${score}/100. Click for report.`;
  }
  statusBar.show();
}

function scanActiveEditor(): void {
  const editor = vscode.window.activeTextEditor;
  if (editor) {
    updateStatusBar(scanAndReport(editor.document));
  } else {
    statusBar.hide();
  }
}

function debouncedScan(document: vscode.TextDocument): void {
  const key = document.uri.toString();
  const existing = debounceTimers.get(key);
  if (existing) {
    clearTimeout(existing);
  }
  debounceTimers.set(
    key,
    setTimeout(() => {
      debounceTimers.delete(key);
      const findings = scanAndReport(document);
      if (vscode.window.activeTextEditor?.document === document) {
        updateStatusBar(findings);
      }
    }, 350)
  );
}

async function scanWorkspace(
  context: vscode.ExtensionContext
): Promise<void> {
  const excludes = config().get<string[]>("excludeGlobs", []);
  const exclude = excludes.length ? `{${excludes.join(",")}}` : undefined;

  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: "Risk Firewall: scanning workspace…",
      cancellable: true,
    },
    async (progress, token) => {
      const files = await vscode.workspace.findFiles(
        "**/*.{js,jsx,ts,tsx,mjs,cjs,py,env,json,yml,yaml,tf,rb,go,php,java,cs,vue,svelte,astro,sh,ps1,lock}",
        exclude,
        4000
      );
      const all: Finding[] = [];
      let done = 0;
      for (const uri of files) {
        if (token.isCancellationRequested) {
          break;
        }
        try {
          const doc = await vscode.workspace.openTextDocument(uri);
          const findings = scanDocument(doc, minSeverity());
          if (findings.length) {
            diagnostics.set(uri, findings.map(findingToDiagnostic));
            all.push(...findings);
          }
        } catch {
          // Unreadable/binary file — skip.
        }
        done++;
        if (done % 25 === 0) {
          progress.report({ message: `${done}/${files.length} files` });
        }
      }
      showReport(context, all, `Workspace scan · ${files.length} files`);
      vscode.window.showInformationMessage(
        `Risk Firewall: ${all.length} finding(s) across ${files.length} files.`
      );
    }
  );
}

export function activate(context: vscode.ExtensionContext): void {
  diagnostics = vscode.languages.createDiagnosticCollection("aiRiskFirewall");
  statusBar = vscode.window.createStatusBarItem(
    vscode.StatusBarAlignment.Right,
    100
  );
  statusBar.command = "aiRiskFirewall.showReport";
  context.subscriptions.push(diagnostics, statusBar);

  // --- commands
  context.subscriptions.push(
    vscode.commands.registerCommand("aiRiskFirewall.scanCurrentFile", () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) {
        vscode.window.showInformationMessage("Risk Firewall: no active file.");
        return;
      }
      const findings = scanAndReport(editor.document);
      updateStatusBar(findings);
      showReport(
        context,
        findings,
        `Current file · ${vscode.workspace.asRelativePath(editor.document.uri)}`
      );
    }),
    vscode.commands.registerCommand("aiRiskFirewall.scanWorkspace", () =>
      scanWorkspace(context)
    ),
    vscode.commands.registerCommand("aiRiskFirewall.showReport", () => {
      const editor = vscode.window.activeTextEditor;
      const findings = editor ? scanAndReport(editor.document) : [];
      showReport(
        context,
        findings,
        editor
          ? `Current file · ${vscode.workspace.asRelativePath(editor.document.uri)}`
          : "No active file"
      );
    }),
    vscode.commands.registerCommand("aiRiskFirewall.generateAgentRules", () =>
      generateAgentRules()
    )
  );

  // --- live watchers
  context.subscriptions.push(
    vscode.window.onDidChangeActiveTextEditor(() => scanActiveEditor()),
    vscode.workspace.onDidOpenTextDocument((doc) => {
      if (vscode.window.activeTextEditor?.document === doc) {
        updateStatusBar(scanAndReport(doc));
      }
    }),
    vscode.workspace.onDidSaveTextDocument((doc) => {
      const findings = scanAndReport(doc);
      if (vscode.window.activeTextEditor?.document === doc) {
        updateStatusBar(findings);
      }
    }),
    vscode.workspace.onDidChangeTextDocument((e) => {
      if (config().get<boolean>("scanOnType", true)) {
        debouncedScan(e.document);
      }
    }),
    vscode.workspace.onDidCloseTextDocument((doc) => {
      // Keep diagnostics for saved files; clear for untitled/closed buffers.
      if (doc.isUntitled) {
        diagnostics.delete(doc.uri);
      }
    })
  );

  // Scan whatever is already open on startup.
  scanActiveEditor();
}

export function deactivate(): void {
  diagnostics?.dispose();
  statusBar?.dispose();
  for (const t of debounceTimers.values()) {
    clearTimeout(t);
  }
}
