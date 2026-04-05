# eval-001 — fieldtheory-cli Security Review

**Date:** 2026-04-05
**Reviewer:** Pi agent (glm-5-turbo, High reasoning)
**Target:** [fieldtheory-cli v1.2.1](https://github.com/afar1/fieldtheory-cli) (commit `2e59f83`)
**Scope:** Full source tree — 16 source files, bin entrypoint, tests, package metadata
**Benchmark:** TPS 89.8 tok/s · out 7,343 · in 44,116 · cache r/w 181,440/0 · total 232,899 · 81.8s

---

## Changelog

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| v1.0 | 2026-04-05 | Pi agent (glm-5-turbo) | Initial review (findings #1–18) |

---

## Summary

Field Theory CLI is a well-structured, local-first tool for syncing X/Twitter bookmarks. The code shows genuine security awareness — correct PKCE implementation, parameterized SQL, prompt injection defenses, and output validation. However, several gaps around **file permissions**, **Chrome credential handling**, and **SSRF** warrant attention before recommending it for broad use.

| Severity | Count |
|----------|-------|
| 🔴 High | 3 |
| 🟡 Medium | 5 |
| 🟢 Low / Info | 7 |
| ✅ Secure | 3 |

---

## 🔴 HIGH

### 1. Chrome Cookie Extraction — No Consent, World-Readable Temp Copies

**File:** `src/chrome-cookies.ts` (lines 10–50, 126–180)

The tool silently extracts and decrypts full X/Twitter session cookies (`ct0` CSRF token + `auth_token`) from Chrome's encrypted cookie store via the macOS Keychain. These are **account-takeover-grade credentials**.

- **No interactive consent prompt.** Extraction fires automatically on `ft sync`. The user sees a welcome message but no `y/N` gate.
- **Keychain probing is broad.** Iterates through 7 browser/service name combinations (Chrome, Google Chrome, Chromium, Brave) with silently swallowed errors.
- **Temp DB copies are world-readable.** When Chrome locks the database, it copies to `/tmp/ft-cookies-<uuid>.db`. On macOS, `/tmp` is `0o1777`, so any local user can read the copied cookie database until deletion.
- **`execFileSync('security', ...)`** triggers Keychain prompts, but failures are caught and silently retried.

**Fix:** Add interactive confirmation. Set `0o600` on temp copies. Log which profile matched. Require explicit `--chrome-profile-directory` instead of auto-detecting.

### 2. Cookies Exposed via CLI Arguments and Shell History

**File:** `src/graphql-bookmarks.ts` (lines 33–36), `src/cli.ts` (sync options)

`csrfToken` and `cookieHeader` can be passed as CLI flags (`--csrf-token`, `--cookie-header`), making them visible in `process.argv`, `ps aux`, and shell history.

**Fix:** Accept credentials from environment variables or stdin only. Remove direct CLI flag support for secrets.

### 3. Sensitive Data Files Are World-Readable

**File:** `src/paths.ts`, `src/fs.ts`

Only `oauth-token.json` is explicitly `chmod 0o600` (`src/xauth.ts` line 55). All other files are created with default umask (`0o644`):

| File | Contains | Permission |
|------|----------|------------|
| `bookmarks.jsonl` | All bookmark data, tweet text, handles | `0o644` |
| `bookmarks.db` | Full-text searchable index | `0o644` |
| `bookmarks-backfill-state.json` | Sync state, bookmark IDs | `0o644` |
| `bookmarks-meta.json` | Sync metadata | `0o644` |
| `media/` | Downloaded images | `0o644` |
| `media-manifest.json` | Media URLs and paths | `0o644` |

On any multi-user system, all local users can read your bookmarks.

**Fix:** `chmod 0o700` on `~/.ft-bookmarks/` and `0o600` on all files within.

---

## 🟡 MEDIUM

### 4. SSRF via Media Fetching

**File:** `src/bookmark-media.ts` (lines 80–130)

`fetch-media` resolves URLs from tweet content (user-controlled) with no validation:
- No domain allowlist/blocklist
- No check for private/internal IPs (`127.0.0.1`, `10.x`, `192.168.x`, `169.254.169.254`, `[::1]`)
- No scheme restriction
- DNS rebinding possible: URL resolves to public IP initially, then to cloud metadata endpoint on fetch

**Fix:** Validate resolved IPs before fetching. Block RFC 1918 / link-local ranges. Allowlist known media CDNs (pbs.twimg.com, etc.).

### 5. Prompt Injection Defense is Fragile

**File:** `src/bookmark-classify-llm.ts` (lines 55–61)

Regex-based input sanitization has gaps — doesn't catch "forget everything", "new role:", unicode confusables, zero-width characters, or base64-encoded instructions. The 300-char truncation limits surface but doesn't prevent short-payload injection.

**Mitigating factors (well done):** Output validation is strong — JSON parsing, ID allowlist against `batchIds`, string filtering, lowercasing. The prompt itself contains a security note. This defense-in-depth approach is reasonable.

**Fix:** Strengthen regex patterns or rely solely on output validation (which is already solid).

### 6. OAuth Callback Server Has No Timeout

**File:** `src/xauth.ts` (lines 96–125)

The HTTP callback server starts with no timeout — runs indefinitely if the user navigates away.

**Fix:** Add `setTimeout` to reject after ~5 minutes and close the server.

### 7. CWD Env File Loading Enables Injection

**File:** `src/config.ts` (lines 14–21)

Env files are loaded from `process.cwd()` before the data directory. Running `ft` from an untrusted directory allows a malicious `.env.local` to inject `FT_CHROME_USER_DATA_DIR`, OAuth credentials, or other variables.

```typescript
const candidatePaths = [
  path.join(process.cwd(), '.env.local'),  // ← dangerous
  path.join(process.cwd(), '.env'),         // ← dangerous
  path.join(dir, '.env.local'),
  path.join(dir, '.env'),
];
```

**Fix:** Only load env from `~/.ft-bookmarks/` or an explicitly specified path.

### 8. Hardcoded Third-Party Bearer Token

**File:** `src/graphql-bookmarks.ts` (line 10)

X's public web-app bearer token is baked into distributed code. It's not secret (embedded in twitter.com's JS), but X could revoke it at any time, silently breaking the tool for all users. Potential ToS concern.

---

## 🟢 LOW / INFORMATIONAL

### 9. User-Agent Spoofing

**File:** `src/graphql-bookmarks.ts` (line 84)

Impersonates Chrome 146. If X starts fingerprinting/blocking this UA, all users break simultaneously.

### 10. No Data Integrity Verification

JSONL cache and SQLite database have no HMAC or signature. An attacker with write access to `~/.ft-bookmarks/` can inject fake bookmarks, modify text (prompt injection vector), or tamper with search results.

### 11. GraphQL Query ID Fragility

**File:** `src/graphql-bookmarks.ts` (line 12)

Depends on an undocumented internal X GraphQL query ID (`Z9GWmP0kP2dajyckAaDUBw`) that can change on any deployment.

### 12. PII Stored in Plaintext

All bookmark data (tweet text, handles, profile URLs, engagement, timestamps) is unencrypted. By design for "local-first self-custody," but users should be aware.

### 13. No Secure Delete

`buildIndex({ force: true })` drops tables but old SQLite pages may remain on disk. `writeJsonLines` overwrites without shredding.

### 14. Error Messages Leak Paths

**File:** `src/chrome-cookies.ts` (line 144)

Error messages include full filesystem paths, leaking directory structure on shared systems.

### 15. Dependency Supply Chain

`npm audit` reports 0 vulnerabilities. Minimal dependency tree (commander, sql.js, sql.js-fts5, dotenv). `^` ranges allow transitive updates. Consider lockfile auditing in CI.

---

## ✅ SECURE — Done Well

### 16. SQL Injection — Properly Defended

All SQLite queries use parameterized bindings (`?` placeholders). FTS5 MATCH queries receive user input via bound parameters. **No SQL injection found.**

### 17. PKCE Implementation is Correct

**File:** `src/xauth.ts` (lines 11–20)

- `verifier` = 32 random bytes, base64url-encoded ✅
- `challenge` = SHA-256 of verifier, base64url-encoded ✅
- `state` = 16 random bytes ✅
- State validation on callback ✅
- Token saved with `0o600` ✅

### 18. LLM Output Validation is Solid

**File:** `src/bookmark-classify-llm.ts` (lines 82–105)

- Response parsed as JSON (not eval'd) ✅
- IDs validated against `batchIds` allowlist ✅
- Categories filtered to non-empty strings, lowercased ✅
- Primary category validated ✅

---

## Priority Fixes

| Priority | Action | Effort |
|----------|--------|--------|
| P0 | `chmod 0o700` on `~/.ft-bookmarks/`, `0o600` on all files | ~10 lines |
| P0 | Add interactive consent before Chrome cookie extraction | ~15 lines |
| P0 | `chmod 0o600` on temp DB copies in `queryCookies()` / `queryDbVersion()` | ~4 lines |
| P1 | Remove `--csrf-token` / `--cookie-header` CLI flags; use env/stdin | ~10 lines |
| P1 | SSRF protection for `fetch-media` — validate resolved IPs, block private ranges | ~30 lines |
| P1 | Add timeout to OAuth callback server | ~5 lines |
| P2 | Remove CWD from env file search paths | ~2 lines |
| P2 | Strengthen prompt injection regexes or document output-validation reliance | ~10 lines |
