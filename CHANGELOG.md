# Changelog

All notable changes to the **AI Code Risk Firewall** extension will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] - 2026-05-30

### Added
- **Inline Suppressions (`src/suppressions.ts`)**: Silencing false positives with comment directives (`risk-firewall-ignore-line`, `risk-firewall-ignore-next-line`, and `risk-firewall-ignore-file`) in any programming language. Comments can be scoped to specific rule IDs (e.g. `secret/openai-key`) or categories.
- **One-Click Quick Fixes (`src/codeActions.ts`)**: Code Action provider adding editor lightbulb quick-fixes (`Ctrl+.` or `Cmd+.`) to auto-insert correct suppression comments matching language comment syntax and indentation.
- **Scan Git Changes Command (`src/gitScan.ts`)**: New command `Risk Firewall: Scan Git Changes (staged / uncommitted)` to scan staged changes, or working-tree changes if nothing is staged, utilizing the built-in VS Code Git API.
- Integrated inline suppressions into `scanner.ts` to ensure ignored findings are excluded from the diagnostics squiggles, status-bar risk score, and webview reports.

## [0.0.1] - 2026-05-30

### Added
- **Local Static Analysis Engine**: Local detection for hardcoded secrets, code injections, SQL injections, XSS, disabled TLS/verify settings, insecure endpoints, and sensitive logging.
- **Dependency Risk Guard**: Scanner for dependency manifests (`package.json`, lock files) to detect package typosquatting, compromised packages, and suspicious install scripts.
- **Interactive Webview Risk Report**: Side-panel dashboard displaying file-specific and workspace-wide risks with a custom 0–100 risk score and direct code navigation.
- **Agent Rules Generator**: Output formats for `.cursorrules`, `.antigravityrules`, `CLAUDE.md`, `AGENTS.md`, and `.github/copilot-instructions.md` derived from the active rule definitions.
- **Live Watcher**: Debounced editor event hooks for real-time diagnostic scanning.
