// The rules engine. Each rule is a regex pattern plus metadata. Detection is
// purely local — no network, no API keys. Patterns intentionally favor recall
// (catch the risky shape) and lean on the human to confirm; messages explain
// the risk in plain English and give a concrete fix.

export type Severity = "critical" | "high" | "medium" | "low";

export type Category =
  | "secret"
  | "auth"
  | "cors"
  | "injection"
  | "xss"
  | "crypto"
  | "network"
  | "config";

export interface Rule {
  /** Stable id, shown as the diagnostic code. */
  id: string;
  title: string;
  category: Category;
  severity: Severity;
  /** Pattern to match against file text. A global flag is added automatically. */
  pattern: RegExp;
  /** Plain-English explanation of why this is risky. */
  message: string;
  /** Concrete suggested fix. */
  fix: string;
  /**
   * Restrict to certain VS Code language ids (e.g. "javascript",
   * "typescriptreact"). Omit to apply to all text files.
   */
  languages?: string[];
  /** Restrict to files whose path matches this pattern (e.g. frontend dirs). */
  filePattern?: RegExp;
}

const JS_LANGS = [
  "javascript",
  "javascriptreact",
  "typescript",
  "typescriptreact",
];

export const RULES: Rule[] = [
  // ---------------------------------------------------------------- secrets
  {
    id: "secret/aws-access-key",
    title: "AWS access key ID",
    category: "secret",
    severity: "critical",
    pattern: /\b(AKIA|ASIA)[0-9A-Z]{16}\b/,
    message: "An AWS access key ID is hardcoded in source.",
    fix: "Move it to an environment variable / secrets manager and rotate the key now.",
  },
  {
    id: "secret/openai-key",
    title: "OpenAI API key",
    category: "secret",
    severity: "critical",
    pattern: /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b/,
    message: "An OpenAI-style secret key is hardcoded in source.",
    fix: "Move it to a server-side env var and rotate the key.",
  },
  {
    id: "secret/anthropic-key",
    title: "Anthropic API key",
    category: "secret",
    severity: "critical",
    pattern: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/,
    message: "An Anthropic API key is hardcoded in source.",
    fix: "Move it to a server-side env var and rotate the key.",
  },
  {
    id: "secret/stripe-secret",
    title: "Stripe secret key",
    category: "secret",
    severity: "critical",
    pattern: /\b(sk|rk)_(live|test)_[A-Za-z0-9]{20,}\b/,
    message: "A Stripe secret key is hardcoded in source.",
    fix: "Use a server-side env var. Never expose Stripe secret keys to the client.",
  },
  {
    id: "secret/google-api-key",
    title: "Google API key",
    category: "secret",
    severity: "high",
    pattern: /\bAIza[0-9A-Za-z_-]{35}\b/,
    message: "A Google API key is hardcoded in source.",
    fix: "Restrict the key by referrer/IP and store it server-side where possible.",
  },
  {
    id: "secret/github-token",
    title: "GitHub token",
    category: "secret",
    severity: "critical",
    pattern: /\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b/,
    message: "A GitHub personal access / app token is hardcoded in source.",
    fix: "Revoke the token immediately and load it from an env var.",
  },
  {
    id: "secret/slack-token",
    title: "Slack token",
    category: "secret",
    severity: "high",
    pattern: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/,
    message: "A Slack token is hardcoded in source.",
    fix: "Rotate the token and store it as a secret.",
  },
  {
    id: "secret/private-key-block",
    title: "Private key block",
    category: "secret",
    severity: "critical",
    pattern: /-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/,
    message: "A private key is embedded in source.",
    fix: "Remove it from the repo, rotate the key pair, and load it from a secret store.",
  },
  {
    id: "secret/jwt-token",
    title: "Hardcoded JWT",
    category: "secret",
    severity: "medium",
    pattern: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/,
    message: "A JWT is hardcoded in source — it may contain or grant access to sensitive data.",
    fix: "Do not commit live tokens. Generate them at runtime.",
  },
  {
    id: "secret/generic-assignment",
    title: "Hardcoded secret assignment",
    category: "secret",
    severity: "high",
    pattern:
      /(?:api[_-]?key|secret|password|passwd|token|access[_-]?token|client[_-]?secret|private[_-]?key)\s*[:=]\s*['"][^'"\s]{8,}['"]/i,
    message: "A credential appears to be assigned a hardcoded literal value.",
    fix: "Replace the literal with a reference to an environment variable.",
  },

  // ------------------------------------------------- secrets in the frontend
  {
    id: "secret/service-role-in-client",
    title: "Service-role / admin key in client code",
    category: "secret",
    severity: "critical",
    pattern: /SERVICE_ROLE|service_role|SUPABASE_SERVICE/,
    languages: JS_LANGS,
    filePattern: /(client|components?|app|pages|src|public|frontend|web)\//i,
    message: "A Supabase service-role (admin) key is referenced in client-side code. It bypasses Row Level Security.",
    fix: "Only use the service-role key on the server (API route / edge function). Use the anon key in the client.",
  },
  {
    id: "secret/next-public-secret",
    title: "Secret exposed via NEXT_PUBLIC_",
    category: "secret",
    severity: "high",
    pattern: /NEXT_PUBLIC_[A-Z0-9_]*(SECRET|KEY|TOKEN|PASSWORD|PRIVATE)/,
    message: "A NEXT_PUBLIC_ env var holds a secret. Anything NEXT_PUBLIC_ is inlined into the browser bundle.",
    fix: "Drop the NEXT_PUBLIC_ prefix and read this only on the server.",
  },

  // ------------------------------------------------------------------- cors
  {
    id: "cors/wildcard-origin",
    title: "Wildcard CORS origin",
    category: "cors",
    severity: "high",
    pattern: /origin\s*:\s*['"]\*['"]|Access-Control-Allow-Origin['"]?\s*[:,]\s*['"]\*['"]/i,
    message: "CORS is configured to allow any origin (*).",
    fix: "Restrict origin to an explicit allowlist of trusted domains.",
  },
  {
    id: "cors/allow-credentials-wildcard",
    title: "CORS credentials with open origin",
    category: "cors",
    severity: "high",
    pattern: /credentials\s*:\s*true/i,
    message: "CORS credentials are enabled — verify the origin is NOT a wildcard, or browsers will leak cookies cross-site.",
    fix: "Pair credentials:true with a specific origin allowlist, never '*'.",
  },

  // ------------------------------------------------------------- injection
  {
    id: "injection/eval",
    title: "Use of eval()",
    category: "injection",
    severity: "high",
    pattern: /\beval\s*\(/,
    languages: JS_LANGS,
    message: "eval() executes arbitrary strings as code and is a common injection vector.",
    fix: "Replace eval with explicit parsing (e.g. JSON.parse) or a safe lookup.",
  },
  {
    id: "injection/function-constructor",
    title: "new Function() from input",
    category: "injection",
    severity: "high",
    pattern: /new\s+Function\s*\(/,
    languages: JS_LANGS,
    message: "new Function() compiles strings into code, equivalent to eval().",
    fix: "Avoid runtime code generation; use data structures or a parser instead.",
  },
  {
    id: "injection/child-process-exec",
    title: "Shell exec with interpolation",
    category: "injection",
    severity: "high",
    pattern: /exec(?:Sync)?\s*\(\s*[`'"][^`'"]*\$\{/,
    languages: JS_LANGS,
    message: "A shell command is built with string interpolation — a command-injection risk.",
    fix: "Use execFile/spawn with an argument array, and validate inputs.",
  },
  {
    id: "injection/sql-string-concat",
    title: "SQL built by string interpolation",
    category: "injection",
    severity: "high",
    pattern: /(?:SELECT|INSERT|UPDATE|DELETE)\b[^;'"`]*(?:\$\{|['"]\s*\+\s*\w+|%s|%d|\.format\(|f['"])/i,
    message: "A SQL query is assembled from interpolated/concatenated values — a SQL-injection risk.",
    fix: "Use parameterized queries / prepared statements with bound parameters.",
  },
  {
    id: "injection/python-os-system",
    title: "os.system / subprocess shell=True",
    category: "injection",
    severity: "high",
    pattern: /os\.system\s*\(|subprocess\.[A-Za-z_]+\([^)]*shell\s*=\s*True/,
    languages: ["python"],
    message: "Running shell commands with user-controllable input invites command injection.",
    fix: "Use subprocess with a list of args and shell=False; validate inputs.",
  },

  // ------------------------------------------------------------------- xss
  {
    id: "xss/dangerously-set-html",
    title: "dangerouslySetInnerHTML",
    category: "xss",
    severity: "high",
    pattern: /dangerouslySetInnerHTML/,
    languages: JS_LANGS,
    message: "dangerouslySetInnerHTML renders raw HTML and can introduce XSS.",
    fix: "Render text normally, or sanitize the HTML (e.g. DOMPurify) before injecting it.",
  },
  {
    id: "xss/inner-html-assign",
    title: "innerHTML assignment",
    category: "xss",
    severity: "medium",
    pattern: /\.innerHTML\s*=/,
    languages: JS_LANGS,
    message: "Assigning to innerHTML with dynamic data can lead to XSS.",
    fix: "Use textContent for text, or sanitize before assigning HTML.",
  },
  {
    id: "xss/document-write",
    title: "document.write()",
    category: "xss",
    severity: "medium",
    pattern: /document\.write\s*\(/,
    languages: JS_LANGS,
    message: "document.write with dynamic content is an XSS and performance risk.",
    fix: "Build DOM nodes explicitly or use a templating/escaping approach.",
  },

  // ----------------------------------------------------------------- crypto
  {
    id: "crypto/weak-hash",
    title: "Weak hash algorithm",
    category: "crypto",
    severity: "medium",
    pattern: /createHash\s*\(\s*['"](md5|sha1)['"]\s*\)|hashlib\.(md5|sha1)\s*\(/i,
    message: "MD5/SHA-1 are broken for security purposes (passwords, signatures, integrity).",
    fix: "Use SHA-256+ for integrity, and bcrypt/scrypt/argon2 for passwords.",
  },
  {
    id: "crypto/math-random-token",
    title: "Math.random() for security value",
    category: "crypto",
    severity: "medium",
    pattern: /(token|secret|nonce|otp|password|salt|key)\s*[:=][^;\n]*Math\.random\s*\(/i,
    message: "Math.random() is not cryptographically secure for tokens/secrets.",
    fix: "Use crypto.randomBytes / crypto.getRandomValues / secrets module.",
  },
  {
    id: "crypto/jwt-hardcoded-secret",
    title: "Hardcoded JWT signing secret",
    category: "crypto",
    severity: "high",
    pattern: /jwt\.sign\s*\([^)]*,\s*['"][^'"]{1,}['"]/,
    languages: JS_LANGS,
    message: "A JWT is signed with a hardcoded string secret.",
    fix: "Load the signing secret from an env var and use a strong, random value.",
  },

  // ---------------------------------------------------------------- network
  {
    id: "network/reject-unauthorized-false",
    title: "TLS verification disabled (rejectUnauthorized:false)",
    category: "network",
    severity: "high",
    pattern: /rejectUnauthorized\s*:\s*false/,
    message: "TLS certificate verification is turned off — enables man-in-the-middle attacks.",
    fix: "Remove this and trust proper CA certs; only disable in throwaway local testing.",
  },
  {
    id: "network/python-verify-false",
    title: "requests verify=False",
    category: "network",
    severity: "high",
    pattern: /verify\s*=\s*False/,
    languages: ["python"],
    message: "TLS certificate verification is disabled for outbound requests.",
    fix: "Remove verify=False; point at the correct CA bundle if needed.",
  },
  {
    id: "network/node-tls-reject-env",
    title: "NODE_TLS_REJECT_UNAUTHORIZED=0",
    category: "network",
    severity: "high",
    pattern: /NODE_TLS_REJECT_UNAUTHORIZED\s*[:=]\s*['"]?0/,
    message: "This env var disables TLS verification process-wide.",
    fix: "Never set this in committed code or production config.",
  },
  {
    id: "network/insecure-http-url",
    title: "Insecure http:// endpoint",
    category: "network",
    severity: "low",
    pattern: /['"]http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)[^'"\s]+['"]/,
    message: "A non-localhost http:// URL is used — traffic is unencrypted.",
    fix: "Use https:// for external endpoints.",
  },

  // ------------------------------------------------------------------ config
  {
    id: "config/debug-true",
    title: "Debug mode enabled",
    category: "config",
    severity: "medium",
    pattern: /debug\s*[:=]\s*True\b|DEBUG\s*[:=]\s*true\b/,
    message: "Debug mode can leak stack traces and internals to users in production.",
    fix: "Drive debug from an env var and default it to off.",
  },
  {
    id: "config/log-sensitive",
    title: "Logging a credential",
    category: "config",
    severity: "medium",
    pattern: /console\.(log|info|debug|error)\s*\([^)]*(password|secret|token|api[_-]?key)/i,
    languages: JS_LANGS,
    message: "A secret-looking value is being written to logs.",
    fix: "Remove the log or redact the sensitive field before logging.",
  },
  {
    id: "config/python-print-sensitive",
    title: "Printing a credential",
    category: "config",
    severity: "low",
    pattern: /print\s*\([^)]*(password|secret|token|api[_-]?key)/i,
    languages: ["python"],
    message: "A secret-looking value is being printed.",
    fix: "Remove the print or redact the sensitive field.",
  },
  {
    id: "auth/token-in-localstorage",
    title: "Token stored in localStorage",
    category: "auth",
    severity: "medium",
    pattern: /localStorage\.(setItem\s*\(\s*['"][^'"]*(token|jwt|auth|session)|[A-Za-z]*[Tt]oken\s*=)/i,
    languages: JS_LANGS,
    message: "Storing auth tokens in localStorage exposes them to any XSS on the page.",
    fix: "Prefer httpOnly, Secure cookies for session tokens.",
  },
];
