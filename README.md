# AI Code Risk Firewall

Catches security, secret, and auth risks in AI-generated code **before you run, commit, or deploy**. It watches the files you (or your coding agent — Claude Code, Cursor, Copilot, Antigravity) change and warns you in real time, right in the editor.

This is not a full enterprise scanner. It is a sharp, change-focused *firewall*: fast, local, and offline.

## What it does

- **Live watcher** — scans the active file as you type (debounced) and on save/open.
- **Inline diagnostics** — risky lines are underlined with a plain-English reason and a concrete fix.
- **Risk score** — a 0–100 score per file in the status bar; click it for a full report.
- **Risk report** — a panel grouping findings by severity with clickable jump-to-line.
- **Workspace scan** — sweep the whole project on demand.

### Detected today (local regex/AST rules, no API key, no network)

Secrets (AWS / OpenAI / Anthropic / Stripe / Google / GitHub / Slack keys, private keys, JWTs, generic credential assignments, `NEXT_PUBLIC_` secret exposure, Supabase service-role key in client code), wildcard CORS, `eval` / `new Function` / shell-exec interpolation, SQL string interpolation, `dangerouslySetInnerHTML` / `innerHTML` / `document.write`, weak hashes (MD5/SHA-1), `Math.random()` for tokens, hardcoded JWT secrets, disabled TLS verification (`rejectUnauthorized:false`, `verify=False`, `NODE_TLS_REJECT_UNAUTHORIZED=0`), insecure `http://` endpoints, debug mode, logging secrets, and tokens in `localStorage`.

## Run it locally

```bash
npm install
npm run build
```

Then press **F5** (Run Extension) to open an Extension Development Host. Open `demo/vulnerable-sample.ts` to see every rule fire.

Commands (Command Palette):

- `Risk Firewall: Scan Current File`
- `Risk Firewall: Scan Whole Workspace`
- `Risk Firewall: Show Risk Report`

## Settings

| Setting | Default | Purpose |
| --- | --- | --- |
| `aiRiskFirewall.enable` | `true` | Master on/off. |
| `aiRiskFirewall.scanOnType` | `true` | Re-scan while typing (else only on save/open). |
| `aiRiskFirewall.minimumSeverity` | `low` | Report only at/above this severity. |
| `aiRiskFirewall.excludeGlobs` | node_modules, dist, build, … | Skipped during workspace scans. |

## Antigravity / fork compatibility

This is a standard VS Code extension and runs unmodified in **Antigravity** and other VS Code forks (Cursor, VSCodium, Windsurf):

- `engines.vscode` is pinned low (`^1.75.0`) so it never demands an API newer than the fork ships.
- It uses only the stable, public `vscode` API — no proprietary Marketplace-only services.
- Package it as a portable `.vsix` (`npm run package`) and install via **Install from VSIX…**, or publish to **Open VSX** (`npm run publish:ovsx`), which forks use instead of the MS Marketplace.

## Package

```bash
npx vsce package          # produces ai-code-risk-firewall-0.1.0.vsix
# or publish to Open VSX:
npx ovsx publish
```

## Add your own rule

Rules live in [`src/rules.ts`](src/rules.ts). Add an entry to the `RULES` array:

```ts
{
  id: "category/short-name",
  title: "Human readable title",
  category: "secret",        // secret | auth | cors | injection | xss | crypto | network | config
  severity: "high",          // critical | high | medium | low
  pattern: /your-regex/,
  message: "Why this is risky.",
  fix: "What to do instead.",
  languages: ["typescript"], // optional: limit to language ids
  filePattern: /client\//,   // optional: limit to file paths
}
```

## Roadmap

- Secret leak guard (dedicated `.env` / frontend tracking)
- Dependency diff (new packages, typosquats, install scripts)
- Pre-commit risk gate
- Framework-specific packs (Next.js, FastAPI, Express, Supabase)
- Optional AI explanations + auto-fix prompt generation (Pro)
- Agent rules generator (`CLAUDE.md`, `AGENTS.md`, `.cursor/rules`, Antigravity rules)

## License

MIT
