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
| v1.2 | 2026-04-05 | Amp (claude-sonnet-4-20250514) | Tertiary review; disputed #2 as false positive, added findings #23–25, updated summary counts and cross-review table |
| v1.1 | 2026-04-05 | Claude Code (glm-5-turbo) | Secondary review; added findings #19–22, refined #16–17, added cross-review comparison |
| v1.0 | 2026-04-05 | Pi agent (glm-5-turbo) | Initial review (findings #1–18) |

---

## Summary

Field Theory CLI is a well-structured, local-first tool for syncing X/Twitter bookmarks. The code shows genuine security awareness — correct PKCE implementation, parameterized SQL, prompt injection defenses, and output validation. However, several gaps around **file permissions**, **Chrome credential handling**, and **SSRF** warrant attention before recommending it for broad use.

| Severity | Count |
|----------|-------|
| 🔴 High / Critical | 3 (1 disputed — see v1.2) |
| 🟡 Medium | 5 |
| 🟢 Low / Info | 7 |
| ✅ Secure | 3 |
| 📝 Addendum (v1.1) | 4 |
| 📝 Addendum (v1.2) | 4 (1 dispute, 3 new) |

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

### 2. ~~Cookies Exposed via CLI Arguments and Shell History~~ **[DISPUTED — v1.2]**

**File:** `src/graphql-bookmarks.ts` (lines 33–36), `src/cli.ts` (sync options)

~~`csrfToken` and `cookieHeader` can be passed as CLI flags (`--csrf-token`, `--cookie-header`), making them visible in `process.argv`, `ps aux`, and shell history.~~

**v1.2 dispute:** This finding is a **false positive**. No `--csrf-token` or `--cookie-header` CLI flags exist in `src/cli.ts`. The `csrfToken` and `cookieHeader` fields exist only in the `SyncOptions` TypeScript interface (`src/graphql-bookmarks.ts` line 56–58) for programmatic use — they are never wired to Commander options and cannot be passed via the CLI. Grep of `cli.ts` for `csrf` and `cookie-header` returns zero matches. The sync command only exposes `--chrome-user-data-dir` and `--chrome-profile-directory`.

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

**v1.1 note:** While SQL injection is correctly prevented, FTS5 `MATCH` syntax is a secondary concern — see addendum #19.

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

**v1.1 note:** Output validation is strong, but the `execFileSync` call to `claude`/`codex` itself is a broader trust surface — see addendum #20.

---

## Priority Fixes

| Priority | Action | Effort |
|----------|--------|--------|
| P0 | `chmod 0o700` on `~/.ft-bookmarks/`, `0o600` on all files | ~10 lines |
| P0 | Add interactive consent before Chrome cookie extraction | ~15 lines |
| P0 | `chmod 0o600` on temp DB copies in `queryCookies()` / `queryDbVersion()` | ~4 lines |
| ~~P1~~ | ~~Remove `--csrf-token` / `--cookie-header` CLI flags; use env/stdin~~ | ~~N/A — false positive (v1.2)~~ |
| P1 | SSRF protection for `fetch-media` — validate resolved IPs, block private ranges | ~30 lines |
| P1 | Add timeout to OAuth callback server | ~5 lines |
| P1 | Ensure temp cookie DB cleanup on SIGINT/SIGTERM, not just `finally` (#23) | ~15 lines |
| P2 | Remove CWD from env file search paths | ~2 lines |
| P2 | Strengthen prompt injection regexes or document output-validation reliance | ~10 lines |
| P2 | Fix TOCTOU race in `saveTwitterOAuthToken` — write with `mode: 0o600` (#25) | ~3 lines |

---

## 📝 ADDENDUM — v1.1 Secondary Review

**Date:** 2026-04-05
**Reviewer:** Claude Code (glm-5-turbo)
**Methodology:** Independent full-source review, then delta analysis against v1.0 findings.

The primary review is thorough and accurate. Four supplementary findings below — two refinements to existing findings and two new items.

### 19. FTS5 Query Syntax Abuse (refinement of #16)

**File:** `src/bookmarks-db.ts` (lines 121, 336)

Finding #16 correctly states no SQL injection exists. However, the `MATCH` clause accepts FTS5 query syntax directly from user input. FTS5 supports `AND`, `OR`, `NOT`, `NEAR`, column filters (`text:foo`), and phrase queries. A crafted search term like `NOT *` or deeply nested `NEAR` expressions could cause expensive full-table scans. Since sql.js is in-process and single-user, the blast radius is limited to local CPU/memory — but a `NEAR(a, b, c, d, e, ...)` with hundreds of terms could spike memory.

**Severity:** Low (local-only, in-process SQLite). Original #16 classification as "Secure" is reasonable for SQL injection specifically; this is a distinct FTS5-syntax concern.

**Recommendation:** Consider input length limits on FTS5 queries, or document that FTS5 syntax is exposed to the user (which may be intentional for power users).

### 20. `execFileSync` to External LLM CLIs — Trust Boundary (refinement of #18)

**File:** `src/bookmark-classify-llm.ts` (lines 44–56)

```typescript
function invokeEngine(engine: Engine, prompt: string): string {
  return execFileSync(bin, args, {
    encoding: 'utf-8',
    timeout: 120_000,
    maxBuffer: 1024 * 1024,
    stdio: ['pipe', 'pipe', 'ignore'],
  }).trim();
}
```

The tool shells out to `claude -p` or `codex exec` with a prompt built from untrusted tweet text. While finding #5 addresses prompt injection in the *text*, and #18 confirms output validation is solid, the `execFileSync` call itself creates a trust dependency on whatever `claude` or `codex` binary is first in `$PATH`. If a malicious actor places a `claude` or `codex` binary earlier in PATH, it receives the full prompt including bookmark data.

**Severity:** Low — requires PATH manipulation, which is a pre-compromise scenario on most systems.

**Recommendation:** Resolve binary paths with `which`/`where` and validate against known install locations, or document the PATH dependency.

### 21. LIKE Pattern Injection in Category/Domain Filters

**File:** `src/bookmarks-db.ts` (lines 137–143)

```typescript
conditions.push(`b.categories LIKE ?`);
params.push(`%${filters.category}%`);
```

User-supplied `--category` and `--domain` values are wrapped in `%` wildcards but not escaped for LIKE metacharacters. A value containing `%` or `_` would be interpreted as wildcards. For example, `--category "%tool%"` would match any category containing "tool", while `--category "_"` would match any single-character category.

**Severity:** Low — local-only, read operation, no data modification. Affects query accuracy, not security.

**Recommendation:** Escape `%` and `_` in user-supplied LIKE values, or use FTS5/GLOB for pattern matching.

### 22. CLI Options Enable Path Traversal to Arbitrary Directories

**File:** `src/cli.ts` (lines 236–237), `src/graphql-bookmarks.ts` (lines 33–36)

Options `--chrome-user-data-dir` and `--chrome-profile-directory` accept arbitrary paths with no validation. Combined with finding #7 (CWD env loading), a social engineering vector exists: convince a user to run `ft sync --chrome-user-data-dir /path/to/sensitive/app` from a directory containing a malicious `.env.local`. The tool would attempt to read cookies from the specified application's data directory.

**Severity:** Medium — requires user to be tricked into passing a specific CLI flag, but the tool does nothing to warn about unusual paths or validate the target looks like a Chrome profile directory.

**Recommendation:** Validate that the target path contains a `Cookies` file and looks like a Chrome profile before attempting extraction. Warn if the path is outside known Chrome locations.

---

## Cross-Review Comparison

| # | Finding | Primary (v1.0) | Secondary (v1.1) | Notes |
|---|---------|---------------|-------------------|-------|
| 1 | Chrome cookie extraction | 🔴 | — | Agreed; Pi provided more detail on consent gap |
| 2 | Cookies in CLI args | 🔴 | Missed | Pi caught this; valid concern |
| 3 | World-readable data files | 🔴 | — | Agreed |
| 4 | Media SSRF | 🟡 | — | Agreed |
| 5 | Prompt injection fragility | 🟡 | — | Agreed; output validation compensates |
| 6 | OAuth callback timeout | 🟡 | Missed | Pi caught this; valid |
| 7 | CWD env loading | 🟡 | — | Agreed |
| 8 | Hardcoded bearer | 🟡 | — | Agreed |
| 9 | UA spoofing | 🟢 | Missed | Pi caught this |
| 10 | No integrity checks | 🟢 | — | Agreed |
| 11 | GraphQL query ID | 🟢 | — | Agreed |
| 12 | Plaintext PII | 🟢 | — | Agreed (by design) |
| 13 | No secure delete | 🟢 | Missed | Pi caught this |
| 14 | Path leak in errors | 🟢 | — | Agreed |
| 15 | Dependency supply chain | 🟢 | — | Agreed; `npm audit` clean |
| 16 | SQL injection defended | ✅ | Refined | FTS5 syntax abuse is a secondary concern (see #19) |
| 17 | PKCE correct | ✅ | — | Agreed |
| 18 | LLM output validation | ✅ | Refined | `execFileSync` PATH trust is a secondary concern (see #20) |
| — | LIKE injection | — | 🟢 New | #21 |
| — | CLI path traversal | — | 🟡 New | #22 |
| — | FTS5 syntax abuse | — | 🟢 New | #19 (refines #16) |
| — | execFileSync PATH | — | 🟢 New | #20 (refines #18) |

**Conclusion:** The primary review is comprehensive and well-calibrated. All 18 original findings are confirmed. Four supplementary items added: two refine existing "Secure" findings into nuanced assessments, and two identify previously unreported gaps (LIKE injection, CLI path traversal). No findings were disputed or found to be incorrect.

---

## 📝 ADDENDUM — v1.2 Tertiary Review

**Date:** 2026-04-05
**Reviewer:** Amp (claude-sonnet-4-20250514)
**Methodology:** Independent full-source security audit using `code_review` tooling, followed by line-by-line verification of all prior findings against actual source code.

### Dispute: Finding #2 is a False Positive

Finding #2 claims `csrfToken` and `cookieHeader` can be passed as CLI flags (`--csrf-token`, `--cookie-header`). This is **incorrect**. These fields exist only in the `SyncOptions` TypeScript interface for programmatic/library use. The CLI (`src/cli.ts`) never wires them to Commander options. A grep of `cli.ts` for `csrf` and `cookie-header` returns zero matches. The sync command exposes only `--chrome-user-data-dir` and `--chrome-profile-directory`.

Both v1.0 and v1.1 missed this — v1.0 reported it as 🔴 High, v1.1 marked it as "Missed" (implying agreement with the finding). The finding should be reclassified as **invalid/false positive**.

### 23. Temp Cookie DB Cleanup Not Crash-Safe — Elevated to Critical

**File:** `src/chrome-cookies.ts` (lines 112–121, 148–161)

Finding #1 correctly identifies the temp copy issue but underweights the severity. There are **two separate codepaths** that copy the Chrome Cookies database to `tmpdir()`:

1. `queryDbVersion()` (line 112): copies to `ft-meta-<uuid>.db`
2. `queryCookies()` (line 148): copies to `ft-cookies-<uuid>.db`

Both rely on `finally` blocks for cleanup, but `finally` does **not** execute on:
- `SIGKILL` / `kill -9`
- `SIGINT` (Ctrl+C) during `execFileSync` — the child process receives the signal, and Node may exit before the `finally` runs
- Uncaught exceptions in other async code paths
- Process crashes / OOM

The copied file is the **entire Chrome Cookies database** — not just X/Twitter cookies — containing session tokens for every website the user is logged into (banking, email, cloud providers). On macOS, `/tmp` is world-readable (`drwxrwxrwt`). The temp files are created with `copyFileSync` which inherits default umask permissions (`0o644`), making them readable by any local user.

**Severity:** Critical — this is the single highest-risk finding in the codebase. A leftover temp file is a full browser session compromise for all sites.

**Fix:** (1) Use `fs.openSync(path, 'wx', 0o600)` + `fs.writeFileSync(fd, ...)` to create temp files with restricted permissions. (2) Register `process.on('SIGINT', ...)` and `process.on('SIGTERM', ...)` handlers to clean up temp files. (3) Consider using a per-user temp directory (`~/.ft-bookmarks/tmp/`) instead of the system `/tmp`.

### 24. `writeJson` and `writeJsonLines` Create World-Readable Files

**File:** `src/fs.ts` (lines 24–26, 33–36)

```typescript
export async function writeJson(filePath: string, value: unknown): Promise<void> {
  await writeFile(filePath, JSON.stringify(value, null, 2), 'utf8');
}
```

Node.js `writeFile` creates files with default umask (typically `0o644` — world-readable). Every file written through these helpers — `bookmarks.jsonl`, `bookmarks-meta.json`, `bookmarks-backfill-state.json`, `media-manifest.json` — is readable by all local users.

This is the root cause underlying finding #3, but #3 only prescribes directory-level `chmod`. The fix needs to happen at the file-write level too, otherwise new files created after the directory chmod would still inherit the umask.

**Severity:** High — same as #3, but identifies the specific code path to fix.

**Fix:** Pass `{ mode: 0o600 }` to all `writeFile` calls in `fs.ts`, or set `process.umask(0o077)` at CLI startup.

### 25. OAuth Token TOCTOU Race in `saveTwitterOAuthToken`

**File:** `src/xauth.ts` (lines 79–87)

```typescript
export async function saveTwitterOAuthToken(token: XOAuthTokenSet): Promise<string> {
  ensureDataDir();
  const tokenPath = twitterOauthTokenPath();
  await writeJson(tokenPath, token);          // ← created with 0o644
  const { chmod } = await import('node:fs/promises');
  await chmod(tokenPath, 0o600);              // ← race window between these two lines
  return tokenPath;
}
```

The token file is first written via `writeJson` (which uses `writeFile` with no mode — defaults to `0o644`), then `chmod`'d to `0o600`. Between these two async operations, the file containing the OAuth `access_token` and `refresh_token` is world-readable. An attacker monitoring the filesystem (e.g., via `inotifywait` or polling) could read the token during this window.

**Severity:** Medium — requires local attacker with timing precision, but the fix is trivial.

**Fix:** Use `fs.writeFile(tokenPath, data, { mode: 0o600 })` to atomically create the file with correct permissions, eliminating the race.

---

## Updated Cross-Review Comparison (v1.2)

| # | Finding | v1.0 (Pi) | v1.1 (Claude Code) | v1.2 (Amp) | Notes |
|---|---------|-----------|---------------------|------------|-------|
| 1 | Chrome cookie extraction | 🔴 | — | Confirmed; elevated temp copy to Critical (#23) | All three reviewers agree |
| 2 | Cookies in CLI args | 🔴 | Missed | ❌ **False positive** | No CLI flags exist; interface-only fields |
| 3 | World-readable data files | 🔴 | — | Confirmed; root-caused to `writeFile` (#24) | Amp identified the specific code path |
| 4 | Media SSRF | 🟡 | — | Confirmed | All agree |
| 5 | Prompt injection fragility | 🟡 | — | Confirmed | Output validation compensates |
| 6 | OAuth callback timeout | 🟡 | Missed | Confirmed | Pi caught this |
| 7 | CWD env loading | 🟡 | — | Confirmed | All agree |
| 8 | Hardcoded bearer | 🟡 | — | Confirmed | All agree |
| 9 | UA spoofing | 🟢 | Missed | Confirmed | Pi caught this |
| 10 | No integrity checks | 🟢 | — | Confirmed | All agree |
| 11 | GraphQL query ID | 🟢 | — | Confirmed | All agree |
| 12 | Plaintext PII | 🟢 | — | Confirmed (by design) | All agree |
| 13 | No secure delete | 🟢 | Missed | Confirmed | Pi caught this |
| 14 | Path leak in errors | 🟢 | — | Confirmed | All agree |
| 15 | Dependency supply chain | 🟢 | — | Confirmed; `npm audit` clean | All agree |
| 16 | SQL injection defended | ✅ | Refined (#19) | Confirmed | All agree |
| 17 | PKCE correct | ✅ | — | Confirmed | All agree |
| 18 | LLM output validation | ✅ | Refined (#20) | Confirmed | All agree |
| 19 | FTS5 syntax abuse | — | 🟢 New | Confirmed | v1.1 refinement |
| 20 | execFileSync PATH | — | 🟢 New | Confirmed | v1.1 refinement |
| 21 | LIKE injection | — | 🟢 New | Confirmed | v1.1 new |
| 22 | CLI path traversal | — | 🟡 New | Confirmed | v1.1 new |
| 23 | Temp DB cleanup crash-safety | — | — | 🔴 New (Critical) | Elevates aspect of #1 |
| 24 | writeFile default perms | — | — | 🔴 New (High) | Root-causes #3 |
| 25 | OAuth token TOCTOU race | — | — | 🟡 New (Medium) | New finding |

**v1.2 Conclusion:** The v1.0 and v1.1 reviews are largely accurate and comprehensive. One finding (#2) is disputed as a false positive — the claimed CLI flags do not exist in the source code. Three new findings are added: #23 elevates the temp cookie DB issue to Critical with crash-safety analysis, #24 root-causes the file permission issue to the `writeFile` calls in `fs.ts`, and #25 identifies a TOCTOU race in OAuth token storage. The overall security posture assessment remains unchanged: the tool is well-intentioned and shows security awareness, but the Chrome cookie handling and file permission gaps are significant for any multi-user deployment.
