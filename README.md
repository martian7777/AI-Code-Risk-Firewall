# 🛡️ AI Code Risk Firewall

[![Version](https://img.shields.io/badge/version-0.1.1-blue.svg?style=flat-square)](https://github.com/martian7777/AI-Code-Risk-Firewall-/releases/tag/v0.1.1)
[![License](https://img.shields.io/badge/license-MIT-green.svg?style=flat-square)](LICENSE)
[![VS Code](https://img.shields.io/badge/editor-VS%20Code%20%2F%20Antigravity-orange.svg?style=flat-square)](package.json)
[![Security](https://img.shields.io/badge/security-local--first-success.svg?style=flat-square)](#-key-features)

Catches security, secret, and authorization risks in AI-generated code **before you run, commit, or deploy**. It watches the files you or your coding agent (Claude Code, Cursor, Copilot, Antigravity) modify and warns you in real-time right inside the editor. 

Unlike heavy enterprise scanners, this is a sharp, change-focused **firewall**: fast, runs entirely local, and operates completely offline.

---

## 🚀 Key Features

* **⚡ Real-Time Change Watcher** — Scans the active file as you type (debounced) and instantly on open or save.
* **🔒 Privacy-First & Offline** — Runs 100% locally using regex/AST patterns. No code ever leaves your machine, and no API keys are required.
* **📊 Live Risk Score** — Calculates a dynamic 0–100 risk score per file and displays it in the status bar (uses diminishing returns so multiple minor alerts don't outweigh a single critical severity issue).
* **📋 Interactive Risk Report** — A rich side-panel webview grouping findings by severity with click-to-reveal jump-to-line navigation.
* **🤖 Agent Rules Generator** — Automatically generates agent instructions (`.cursorrules`, `.antigravityrules`, `CLAUDE.md`, `AGENTS.md`, or `.github/copilot-instructions.md`) derived from the active firewall rules to stop agents from writing vulnerable code in the first place.
* **📦 Dependency Diff Watcher** — Inspects manifests and lock files (`package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`) for typosquats of popular packages, known compromised versions, and suspicious lifecycle install scripts.
* **💡 One-Click Quick Fixes** — Every finding gets lightbulb actions: silence a false positive on a single line, mute a noisy rule for the whole file, or jump straight to the full report — no manual comment typing.
* **🙈 Inline Suppressions** — Mark intentional code with ordinary comments the firewall reads back in: `risk-firewall-ignore-line`, `risk-firewall-ignore-next-line`, or `risk-firewall-ignore-file` (optionally scoped to specific rule ids). Works in any language.
* **🔀 Scan Git Changes** — One command scans exactly what you're about to commit — your **staged** changes (or working-tree changes when nothing's staged) — so AI-written diffs get a security gate before they land.

---

## 🔍 Security Rules & Detection Engine

The firewall categorizes and reports vulnerabilities across several dimensions:

### 1. Hardcoded Secrets (`secret`)
* **AWS access key IDs** (`AKIA...` / `ASIA...`) — [Critical]
* **OpenAI API keys** (`sk-...`) — [Critical]
* **Anthropic API keys** (`sk-ant-...`) — [Critical]
* **Stripe secret/restricted keys** (`sk_live...` / `rk_test...`) — [Critical]
* **Google API keys** (`AIza...`) — [High]
* **GitHub tokens** (`ghp_...` / `gho_...`) — [Critical]
* **Slack tokens** (`xoxb-...` / `xoxp-...`) — [High]
* **Private Key blocks** (`BEGIN PGP/RSA/EC PRIVATE KEY`) — [Critical]
* **JSON Web Tokens** (`eyJ...`) — [Medium]
* **Generic assignments** (`api_key = "..."`, `password = "..."`) — [High]
* **Frontend exposure** — Service role keys (`SERVICE_ROLE`) in frontend directories or secrets prefixed with `NEXT_PUBLIC_` — [Critical/High]

### 2. Dependency Risk Guard (`dependency`)
* **Typosquatting** — Checks if added packages are single-edit-distance typos of the top 50 most-used packages (e.g. `lodaash` instead of `lodash`). — [Critical]
* **Compromised Packages** — Identifies packages tied to publicized supply-chain incidents (e.g. `event-stream` malicious versions, `node-ipc` protestware, `sabotaged colors/faker`). — [High]
* **Lifecycle Install Scripts** — Flags `preinstall`, `install`, or `postinstall` commands in `package.json` that invoke shell, network, base64 decoding, or execution scripts. — [High/Medium]

### 3. Attack & Injection Vectors
* **Code Injection (`injection`)** — Use of `eval()`, `new Function()`, shell commands with string interpolation (`exec("...${var}")`), and Python `os.system()` or `shell=True` subprocesses. — [High]
* **SQL Injection (`injection`)** — Assembled queries via interpolation or concatenation instead of parameterized queries. — [High]
* **Cross-Site Scripting (`xss`)** — Use of `dangerouslySetInnerHTML`, `.innerHTML` assignments, and `document.write()`. — [High/Medium]

### 4. Encryption & Networks
* **Weak Cryptography (`crypto`)** — Use of MD5 or SHA-1 for hashing, hardcoded JWT signing secrets, or `Math.random()` to generate security tokens. — [High/Medium]
* **Disabled TLS (`network`)** — Bypassing server certificate verification (`rejectUnauthorized: false`, python `verify=False`, or setting `NODE_TLS_REJECT_UNAUTHORIZED=0`). — [High]
* **Insecure Endpoints (`network`)** — Outbound remote requests utilizing plaintext `http://` instead of `https://`. — [Low]

### 5. Config & Logging (`config` / `auth`)
* **Debug Mode** — Static debug switches (`DEBUG = true`) left active in production. — [Medium]
* **Sensitive Logs** — Logging or printing secret variables (`console.log(password)`). — [Medium/Low]
* **Session Storage (`auth`)** — Storing tokens/sessions in `localStorage` instead of Secure, httpOnly cookies. — [Medium]

---

## Walkthrough 


<img width="1482" height="821" alt="image" src="https://github.com/user-attachments/assets/51e82dfb-1072-4ab6-ac1b-056c8409bc8d" />

<img width="594" height="128" alt="image" src="https://github.com/user-attachments/assets/7a197f2f-d761-4136-8fc5-f8b6b3d5c452" />


## 🛒 Installation & Marketplace

### In the Editor (VS Code / Antigravity / Cursor / VSCodium)
Open the **Extensions** side panel in your editor and search for:
* **`martian7777.ai-code-risk-firewall`** (the unique extension ID)
* Or simply search: **`AI Code Risk Firewall`**

### On the Web
You can also view and install the extension directly from the public registries:
* **VS Code Marketplace**: [https://marketplace.visualstudio.com/items?itemName=martian7777.ai-code-risk-firewall](https://marketplace.visualstudio.com/items?itemName=martian7777.ai-code-risk-firewall)
* **Open VSX Registry**: [https://open-vsx.org/extension/martian7777/ai-code-risk-firewall](https://open-vsx.org/extension/martian7777/ai-code-risk-firewall)

---

## 🛠️ Getting Started

### Local Setup
1. Clone the repository and install the development dependencies:
   ```bash
   npm install
   ```
2. Build the extension:
   ```bash
   npm run build
   ```
3. Open the repository in VS Code or Antigravity and press **F5** (or go to *Run and Debug* -> *Run Extension*).
4. An **Extension Development Host** window will open. Open the `demo/vulnerable-sample.ts` file in that window to see the real-time firewall diagnostics in action!

### Commands List
Access these via the Command Palette (`Ctrl+Shift+P` or `Cmd+Shift+P`):
* `Risk Firewall: Scan Current File` — Run an immediate scan on the active editor and show report.
* `Risk Firewall: Scan Whole Workspace` — Scan all project files (ignoring excluded paths) and compile a project-wide report.
* `Risk Firewall: Scan Git Changes (staged / uncommitted)` — Scan only the files you're about to commit and report on them.
* `Risk Firewall: Show Risk Report` — View the live report panel side-by-side with your code.
* `Risk Firewall: Generate Agent Security Rules` — Create customized rules for AI coding assistants.

### Suppressing False Positives
The firewall is built for recall, so it occasionally flags intentional code. Silence a finding with a comment — use your language's comment syntax (`//`, `#`, `--`, …):

```js
const apiKey = process.env.OPENAI_KEY ?? "sk-localtestkeyonly"; // risk-firewall-ignore-line secret/openai-key

// risk-firewall-ignore-next-line
eval(trustedExpression);
```

* Append no rule id to silence **every** finding at that location, or list one or more ids/categories (comma- or space-separated) to scope it: `risk-firewall-ignore-line secret, cors`.
* Place `risk-firewall-ignore-file` anywhere in a file to mute matching rules for the whole file.
* The easiest way to add these is the **lightbulb / Quick Fix menu** (`Ctrl+.`) on any flagged line — it writes the comment for you.

---

## ⚙️ Configuration

You can customize the firewall behavior via your workspace `settings.json`:

| Setting | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `aiRiskFirewall.enable` | `boolean` | `true` | Enables/disables the real-time scanning engine. |
| `aiRiskFirewall.scanOnType` | `boolean` | `true` | Re-scans files as you type (debounced). Set to `false` to scan only on save or open. |
| `aiRiskFirewall.minimumSeverity` | `string` | `"low"` | Only report findings at or above this severity. Options: `low`, `medium`, `high`, `critical`. |
| `aiRiskFirewall.excludeGlobs` | `string[]` | `["**/node_modules/**", "**/dist/**", "**/build/**", "**/.git/**", "**/out/**"]` | Glob patterns to ignore during workspace scans. |

---

## 📋 Release Notes

### v0.1.1

Makes findings **actionable** — the firewall now helps you fix and dismiss risks, not just spot them.

1. **One-Click Quick Fixes** — Lightbulb code actions (`Ctrl+.`) on any flagged line: silence a single false positive, mute a noisy rule for the whole file, or jump to the full report. The suppression comment is written for you with the correct comment syntax and indentation.
2. **Inline Suppressions** — Honor `risk-firewall-ignore-line`, `risk-firewall-ignore-next-line`, and `risk-firewall-ignore-file` comments (optionally scoped to specific rule ids/categories) in any language. Suppressed findings drop out of diagnostics, the status-bar score, and the report.
3. **Scan Git Changes** — New `Risk Firewall: Scan Git Changes` command scans exactly what you're about to commit (staged changes, or working-tree changes when nothing is staged) via the built-in Git API — no extra dependencies.

### v0.0.1 (Initial Release)

This is the first release of the **AI Code Risk Firewall** VS Code extension.

#### What's Implemented:
1. **Security & Secrets Linting Engine** — 30+ regex-based static analysis rules running locally in Node.js to capture high-severity leaks and common vulnerabilities.
2. **Local Dependency Diff Watcher** — Offline manifest analysis in `package.json` and lock files checking for typosquats, flagged protestware/malware packages, and automatic install hooks.
3. **Interactive Webview Risk Report** — A customized panel summarizing workspace/file health with a custom 0-100 risk score and direct code navigation links.
4. **Agent Rules Generator** — A generator targeting `.cursorrules`, `.antigravityrules`, `CLAUDE.md`, `AGENTS.md`, and `.github/copilot-instructions.md` to instruct AI models on security patterns automatically.
5. **Debounced Live Watcher** — Seamless editor integrations utilizing diagnostics markers without slowing down typing or compiler performance.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
