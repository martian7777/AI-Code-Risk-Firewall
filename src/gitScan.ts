// "Scan Git Changes" command. The firewall's whole pitch is catching risky AI
// code *before* it ships, so the most natural gate is the set of files you're
// about to commit. This reads the built-in Git extension's API (no shelling
// out, no extra deps), scans the staged changes — or the working-tree changes
// when nothing is staged yet — and routes findings through the same
// diagnostics + report pipeline as every other scan.

import * as vscode from "vscode";
import { Finding, scanDocument, findingToDiagnostic } from "./scanner";
import { Severity } from "./rules";

// Minimal shape of the parts of the vscode.git API we touch. Typed loosely so
// we don't need to bundle the git extension's d.ts.
interface GitChange {
  uri: vscode.Uri;
}
interface GitRepoState {
  indexChanges: GitChange[];
  workingTreeChanges: GitChange[];
}
interface GitRepository {
  rootUri: vscode.Uri;
  state: GitRepoState;
}
interface GitAPI {
  repositories: GitRepository[];
}

function getGitApi(): GitAPI | undefined {
  const ext = vscode.extensions.getExtension<{ getAPI(version: 1): GitAPI }>(
    "vscode.git"
  );
  return ext?.isActive ? ext.exports.getAPI(1) : undefined;
}

/** Collect the URIs to scan: staged changes if any, else working-tree changes. */
function changedUris(api: GitAPI): { uris: vscode.Uri[]; staged: boolean } {
  const staged: vscode.Uri[] = [];
  const dirty: vscode.Uri[] = [];
  for (const repo of api.repositories) {
    for (const c of repo.state.indexChanges) {
      staged.push(c.uri);
    }
    for (const c of repo.state.workingTreeChanges) {
      dirty.push(c.uri);
    }
  }
  const dedupe = (list: vscode.Uri[]) => {
    const seen = new Set<string>();
    return list.filter((u) => {
      const key = u.toString();
      if (seen.has(key)) {
        return false;
      }
      seen.add(key);
      return true;
    });
  };
  return staged.length
    ? { uris: dedupe(staged), staged: true }
    : { uris: dedupe(dirty), staged: false };
}

export async function scanGitChanges(
  diagnostics: vscode.DiagnosticCollection,
  minSeverity: Severity,
  showReport: (findings: Finding[], scope: string) => void
): Promise<void> {
  const ext = vscode.extensions.getExtension("vscode.git");
  if (ext && !ext.isActive) {
    try {
      await ext.activate();
    } catch {
      /* fall through to the no-git message below */
    }
  }

  const api = getGitApi();
  if (!api) {
    vscode.window.showWarningMessage(
      "Risk Firewall: the built-in Git extension isn't available, so changed files can't be detected."
    );
    return;
  }
  if (api.repositories.length === 0) {
    vscode.window.showInformationMessage(
      "Risk Firewall: no Git repository found in this workspace."
    );
    return;
  }

  const { uris, staged } = changedUris(api);
  if (uris.length === 0) {
    vscode.window.showInformationMessage(
      "Risk Firewall: no changed files to scan — working tree is clean."
    );
    return;
  }

  const all: Finding[] = [];
  let scanned = 0;
  for (const uri of uris) {
    try {
      const doc = await vscode.workspace.openTextDocument(uri);
      const findings = scanDocument(doc, minSeverity);
      scanned++;
      if (findings.length) {
        diagnostics.set(uri, findings.map(findingToDiagnostic));
        all.push(...findings);
      }
    } catch {
      // Deleted file, binary, or otherwise unreadable — skip.
    }
  }

  const label = staged ? "staged" : "uncommitted";
  showReport(all, `Git ${label} changes · ${scanned} file(s)`);

  const verb = all.length ? `⚠ ${all.length} finding(s)` : "✅ no risks";
  vscode.window.showInformationMessage(
    `Risk Firewall: ${verb} across ${scanned} ${label} file(s).`
  );
}
