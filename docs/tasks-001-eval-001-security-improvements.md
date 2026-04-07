# tasks-001 — Security Improvements from eval-001

**Source:** [eval-001-fieldtheory-cli-security-review.md](./eval-001-fieldtheory-cli-security-review.md)
**Created:** 2026-04-05
**Status:** 🟡 Open
**Version:** v1.3
**Baseline:** `upstream/main` @ `83265d0` (merged PRs #36–#40, v1.2.2+)

---

## Changelog

| Version | Date | Author | Changes |
|---------|------|--------|--------|
| v1.3 | 2026-04-05 | Pi agent (review) | Re-baselined all 12 tasks against upstream/main. Upstream landed `5af58f7` (atomic writes, dir perms) and `84a55b8` (private writes, cross-platform browser support, SIGINT handler). T02 closed (done upstream). T03, T07, T11 reduced to remaining gaps. T04 and T08 rewritten for new `--cookies`/`--browser` flags and `browsers.ts` registry. T01 updated for SIGINT handler conflict with `createSpinner`. T06 line refs updated. New upstream gap: `gaps-failures.json` written without restricted perms. |
| v1.2 | 2026-04-05 | Amp (claude-sonnet-4-20250514) | Applied v1.1 peer review: fixed T01 Node API bug, upgraded T08 warn→error+force, added cross-task notes to T02/T03, clarified T04 prompt timing, marked line refs as approximate, resolved both open clarifications. |
| v1.1 | 2026-04-05 | Pi agent (review) | Added versioning, changelog, reviewer notes section. Verified source code against all 12 tasks — resolved 5 questions, flagged 2 remaining clarifications, 1 cross-platform concern. |
| v1.0 | 2026-04-05 | Amp (claude-sonnet-4-20250514) | Initial task breakdown from eval-001 findings. |

---

## Overview

Actionable task breakdown for all security findings from eval-001 (v1.0–v1.2).
Each task is self-contained with file scope, acceptance criteria, and test approach.
Tasks within a phase can be worked in parallel unless a dependency is noted.

### Phasing

| Phase | Priority | Theme | Tasks |
|-------|----------|-------|-------|
| **Phase 0** | P0 — Critical/High | File permissions & cookie safety | T01, T03, T04 |
| **Phase 1** | P1 — Medium | Network, auth, trust boundaries | T05–T08 |
| **Phase 2** | P2 — Low/Hardening | Env loading, input sanitization, cleanup | T09–T12 |

### Dependency Graph

```
T03 (file perms) ──► T07 (remove redundant chmod) — scope reduced to cleanup only
T01 (temp DB)      ── independent (but note SIGINT conflict with createSpinner)
T04 (consent gate) ── independent
T05–T12            ── all independent of each other
```

### Upstream changes since v1.0

The following upstream commits landed between the eval baseline (`2e59f83`, v1.2.1) and the current main (`83265d0`), affecting multiple tasks:

| Commit | Summary | Tasks affected |
|--------|---------|---------------|
| `5af58f7` | Atomic writes (`.tmp`+rename), dir perms `0o700`, FTS5 error handling | T02, T03, T11 |
| `7c092b4` | Graceful SIGINT via `createSpinner` (`process.once`) | T01 |
| `84a55b8` | Private writes (`WriteOptions.mode`), cross-platform browsers, `--cookies` flag, `browsers.ts` registry | T03, T04, T07, T08 |

New files added: `src/browsers.ts`, `src/engine.ts`, `src/preferences.ts`, `src/firefox-cookies.ts`.

---

## Phase 0 — Critical / High

### ~~T02 · Restrict data directory permissions~~ ✅ DONE (upstream)

<!-- eval-001: #3 -->

**Status:** Closed — fully addressed by upstream `5af58f7`.

`ensureDirSync()` in `src/paths.ts` now uses `mode: 0o700`. The `ensureDataDir()` function creates the data directory with restricted permissions on fresh installs. Remaining gap (not tasked — acceptable): `ensureDataDir()` does not `chmodSync` for pre-existing directories with wrong perms. This is a one-time migration concern and not worth a separate task.

---

### T01 · Crash-safe temp cookie DB handling
<!-- eval-001: #1, #23 -->

**Findings:** #1 (chrome cookie temp copies), #23 (crash-safety elevation)
**Files:** `src/chrome-cookies.ts`, `src/firefox-cookies.ts`
**Risk:** Critical — leftover temp file in `/tmp` exposes entire browser Cookies DB
**Upstream delta:** `chrome-cookies.ts` now supports Linux/Windows/Firefox. `firefox-cookies.ts` is a new file with its own temp copy pattern (not yet checked for this issue).

#### What to do

1. In `queryDbVersion()` (~line 269) and `queryCookies()` (~line 281) in `src/chrome-cookies.ts`, replace `copyFileSync(dbPath, tmpDb)` with a restricted-permission copy:
   ```typescript
   import { writeFileSync, readFileSync } from 'node:fs';
   // ...
   writeFileSync(tmpDb, readFileSync(dbPath), { mode: 0o600 });
   ```
2. Audit `src/firefox-cookies.ts` for the same pattern — it also uses `copyFileSync` to `/tmp` and needs the same fix.
3. Register process-level signal handlers to track and clean up temp files on unexpected exit. Add a module-level `Set<string>` of active temp paths and clean them on `SIGINT`/`SIGTERM`:
   ```typescript
   const activeTempFiles = new Set<string>();

   function cleanupTempFiles() {
     for (const f of activeTempFiles) {
       try { unlinkSync(f); } catch {}
     }
     activeTempFiles.clear();
   }

   // NOTE (v1.3): createSpinner() in cli.ts registers process.once('SIGINT', ...)
   // that calls process.exit(0). This CONSUMES the first SIGINT, preventing
   // our handler from firing. If the spinner is active during sync, temp files
   // won't be cleaned up on Ctrl+C.
   //
   // Options:
   // (a) Have createSpinner call cleanupTempFiles() before exiting.
   // (b) Use process.prependListener('SIGINT', ...) instead of process.on —
   //     prependListener fires BEFORE once-registered listeners.
   // (c) Move cleanup into the finally block only (current approach) and
   //     accept the gap for SIGKILL/OOM.
   //
   // Recommended: (b) — prependListener is the least invasive.
   process.prependListener('SIGINT', () => { cleanupTempFiles(); });
   process.prependListener('SIGTERM', () => { cleanupTempFiles(); });
   ```
   > **Why `prependListener` not `on`:** `process.once` (used by `createSpinner`) removes itself after one invocation. `prependListener` adds our handler before it in the queue, so ours fires first. We do NOT call `process.exit()` — we let the spinner's handler (or the default Node behavior) handle that.

4. Add temp file to the set before creation, remove in `finally`.

#### Acceptance criteria

- [ ] Temp files created with `0o600` (verify: `stat` on a temp file if browser is open and DB is locked)
- [ ] `SIGINT` during sync does not leave files matching `ft-cookies-*` or `ft-meta-*` in `/tmp`
- [ ] `firefox-cookies.ts` temp copies also use `0o600`
- [ ] Existing sync functionality is unaffected (run `ft sync` end-to-end)

#### Test approach

```bash
# Manual: start ft sync, Ctrl+C mid-sync, then check:
ls /tmp/ft-cookies-* /tmp/ft-meta-* /tmp/ft-firefox-* 2>/dev/null && echo "FAIL" || echo "PASS"
```

Unit test: mock `copyFileSync` to throw after creation, verify cleanup runs.

---

### T03 · Default file write permissions
<!-- eval-001: #3, #24 -->

**Findings:** #3 (world-readable files), #24 (root cause in `writeFile`)
**Files:** `src/fs.ts`, `src/paths.ts`
**Risk:** High — most data files created with default umask permissions
**Upstream delta:** Upstream added atomic `.tmp`+rename writes and a `WriteOptions.mode` parameter, but mode defaults to `undefined` (inherits umask). Only `xauth.ts` and `preferences.ts` pass `{ mode: 0o600 }` explicitly.
**Dependency:** Landing this completes T07 (redundant chmod removal).

#### What to do

1. Make `0o600` the **default** mode in `writeJson()` and `writeJsonLines()`:
   ```typescript
   export async function writeJson(filePath: string, value: unknown, options: WriteOptions = {}): Promise<void> {
     const tmp = filePath + '.tmp';
     await writeFile(tmp, JSON.stringify(value, null, 2), { encoding: 'utf8', mode: options.mode ?? 0o600 });
     await rename(tmp, filePath);
   }

   export async function writeJsonLines(filePath: string, rows: unknown[], options: WriteOptions = {}): Promise<void> {
     const tmp = filePath + '.tmp';
     const content = rows.map((row) => JSON.stringify(row)).join('\n') + (rows.length ? '\n' : '');
     await writeFile(tmp, content, { encoding: 'utf8', mode: options.mode ?? 0o600 });
     await rename(tmp, filePath);
   }
   ```
2. Update `ensureDir()` in `src/fs.ts` to use `mode: 0o700`:
   ```typescript
   export async function ensureDir(dirPath: string): Promise<void> {
     await mkdir(dirPath, { recursive: true, mode: 0o700 });
   }
   ```
3. Verify `ensureDirSync()` in `src/paths.ts` already uses `mode: 0o700` (it does — upstream `5af58f7`).
4. Remove the now-unnecessary explicit `{ mode: 0o600 }` from callers:
   - `src/xauth.ts:82` — `writeJson(tokenPath, token, { mode: 0o600 })` → `writeJson(tokenPath, token)`
   - `src/preferences.ts:17` — `fs.writeFileSync(tmpPath, ..., { mode: 0o600 })` — this uses sync `writeFileSync` directly, not `writeJson()`. Either migrate to `writeJson` or keep the explicit mode.

#### Acceptance criteria

- [ ] `bookmarks.jsonl`, `bookmarks-meta.json`, `bookmarks-backfill-state.json`, `media-manifest.json` all created with `0o600` (without callers passing explicit mode)
- [ ] `media/` subdirectory created with `0o700`
- [ ] `xauth.ts` no longer passes explicit `{ mode: 0o600 }` (default handles it)
- [ ] All existing tests pass (`npm test`)

#### Test approach

Unit test: write a JSON file via `writeJson()` to a temp path with no options, stat it, assert mode is `0o600`.

---

### T04 · Interactive consent before browser cookie extraction
<!-- eval-001: #1 -->

**Findings:** #1 (no consent prompt)
**Files:** `src/cli.ts` (sync command action)
**Risk:** High — silent credential extraction on first run
**Upstream delta:** Major scope changes:
- `--cookies <ct0> [auth_token]` flag bypasses browser extraction entirely.
- `--browser <name>` flag replaces direct `--chrome-user-data-dir` for normal use.
- `chrome-cookies.ts` is now cross-platform (Linux/Windows/Firefox).
- `showSyncWelcome()` now lists available browser IDs.
- `--yes` flag already exists on the sync command (used for `--rebuild` confirmation).
- `isFirstRun()` still checks `!existsSync(twitterBookmarksCachePath())`.

#### What to do

1. On **first run only** (when `isFirstRun()` is true, not using `--api`, and not using `--cookies`), prompt the user before extracting browser cookies:
   ```
   ⚠  Field Theory needs to read your browser session cookies for x.com
      to sync your bookmarks. No credentials are stored or transmitted.

      Detected browser: Google Chrome
      Cookies will be read from: ~/Library/Application Support/Google/Chrome/Default/Cookies

      Continue? [y/N]
   ```
2. Show the resolved browser name and cookie DB path. Use `loadChromeSessionConfig()` to resolve the actual `browser.displayName` and cookie path, but do this **after** the consent check to avoid triggering keychain access before the user agrees.
3. Use Node's `readline` to read a single line from stdin. Default to "no" on empty input.
4. On subsequent runs (cache file already exists), skip the prompt — the user has already consented.
5. Reuse the existing `--yes` / `-y` flag (already registered on the sync command for `--rebuild`).

> **Timing:** In `cli.ts`, the current sync flow is: `isFirstRun()` → `showSyncWelcome()` → `ensureDataDir()` → cookie extraction. Insert the consent prompt **after** `showSyncWelcome()` and `ensureDataDir()` (both harmless) but **before** `syncBookmarksGraphQL()` is called. If the user declines, exit before any cookie/network activity. Skip the prompt entirely if `options.cookies` is provided (user explicitly passed tokens) or `options.api` is true.

#### Acceptance criteria

- [ ] First `ft sync` shows consent prompt; answering `n` or empty exits cleanly
- [ ] First `ft sync` with `--yes` skips the prompt
- [ ] First `ft sync --cookies <ct0> <auth>` skips the prompt (cookies passed directly)
- [ ] Second `ft sync` (cache file exists) does not prompt
- [ ] `ft sync --api` never prompts (doesn't use cookies)
- [ ] Prompt shows the detected browser name and resolved cookie DB path

#### Test approach

Manual verification on a clean install. Unit test: mock `isFirstRun()` → true, verify readline is called.

---

## Phase 1 — Medium

### T05 · SSRF protection for media fetching
<!-- eval-001: #4 -->

**Findings:** #4 (SSRF via media fetching)
**Files:** `src/bookmark-media.ts`
**Risk:** Medium — user-controlled URLs fetched without validation
**Upstream delta:** No changes to this file. Still fully open.

#### What to do

1. Before the `fetch(sourceUrl, { method: 'HEAD' })` call (~line 107), validate the URL:
   - Parse with `new URL(sourceUrl)` — reject on failure
   - Reject non-`https:` schemes
   - Resolve hostname via `dns.lookup()` and reject RFC 1918, loopback, link-local, and metadata IPs:
     ```
     127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16,
     169.254.0.0/16, ::1, fc00::/7, fe80::/10
     ```
2. Optionally allowlist known Twitter/X media CDNs (`pbs.twimg.com`, `video.twimg.com`, `abs.twimg.com`) and skip DNS checks for them.
3. Extract the validation into a `validateMediaUrl(url: string): Promise<void>` helper that throws on rejection.

#### Acceptance criteria

- [ ] `http://` URLs rejected
- [ ] `file:///etc/passwd` rejected
- [ ] URLs resolving to `127.0.0.1`, `10.x`, `192.168.x`, `169.254.169.254` rejected
- [ ] Normal Twitter media URLs (`pbs.twimg.com/...`) still work
- [ ] Rejection logged as `status: 'failed'` with reason in manifest

#### Test approach

Unit test with mocked DNS resolution returning private IPs. Integration test: add a bookmark with a `http://127.0.0.1/` media URL, run `ft fetch-media`, verify it's rejected.

---

### T06 · OAuth callback server timeout
<!-- eval-001: #6 -->

**Findings:** #6 (no timeout on callback server)
**Files:** `src/xauth.ts`
**Risk:** Medium — server hangs indefinitely if user abandons flow
**Upstream delta:** No functional changes to `runTwitterOAuthFlow()`. Still fully open. Line numbers shifted due to earlier file changes.

#### What to do

1. In `runTwitterOAuthFlow()`, add a timeout to the Promise. The server is created inside the Promise constructor, so `server` and `timer` are both in scope:
   ```typescript
   const OAUTH_TIMEOUT_MS = 5 * 60 * 1000; // 5 minutes

   const code = await new Promise<string>((resolve, reject) => {
     const server = http.createServer((req, res) => {
       // ... existing handler ...
     });

     const timer = setTimeout(() => {
       server.close();
       reject(new Error(
         'OAuth flow timed out after 5 minutes.\n' +
         'Run ft auth again to restart.'
       ));
     }, OAUTH_TIMEOUT_MS);

     server.listen(port, '127.0.0.1', () => {
       console.log('Open this URL in your browser to authorize X bookmarks access:');
       console.log(url);
     });

     // In the existing success/error handlers inside createServer,
     // add: clearTimeout(timer);
   });
   ```
2. Clear the timeout on both success and error paths in the existing request handler.

#### Acceptance criteria

- [ ] Server auto-closes after 5 minutes with a clear error message
- [ ] Successful auth within 5 minutes works as before
- [ ] Timer is cleared on success (no dangling timeout)

#### Test approach

Unit test: start the OAuth flow with a 1-second timeout override, verify it rejects with timeout error.

---

### T07 · Remove redundant OAuth token chmod
<!-- eval-001: #25 -->

**Findings:** #25 (write-then-chmod race)
**Files:** `src/xauth.ts`
**Risk:** Low — race window eliminated by upstream's `writeJson` with `{ mode: 0o600 }`
**Upstream delta:** `saveTwitterOAuthToken()` now passes `{ mode: 0o600 }` to `writeJson`. The `.tmp`+rename atomic write means the file is created with correct perms before rename. The `chmod` call on the next line is now fully redundant.
**Dependency:** If T03 lands first (making `0o600` the default), this becomes even simpler.

#### What to do

1. Remove the redundant `chmod` block (~lines 83–85):
   ```typescript
   // BEFORE:
   await writeJson(tokenPath, token, { mode: 0o600 });
   // Restrict permissions — OAuth tokens should only be readable by the owner
   const { chmod } = await import('node:fs/promises');
   await chmod(tokenPath, 0o600);

   // AFTER:
   await writeJson(tokenPath, token);
   // mode: 0o600 is set by writeJson (either explicit default or caller-passed)
   ```
2. If T03 has landed (making `0o600` the default), the explicit `{ mode: 0o600 }` can also be dropped.

#### Acceptance criteria

- [ ] No `chmod` call in `saveTwitterOAuthToken`
- [ ] Token file still created with `0o600` (verified by `stat`)
- [ ] `ft auth` flow completes successfully

#### Test approach

```bash
ft auth  # complete the flow
stat -c "%a" ~/.ft-bookmarks/oauth-token.json  # Linux
# macOS: stat -f "%Lp" ~/.ft-bookmarks/oauth-token.json
# Expected: 600
```

---

### T08 · CLI path validation for browser cookie extraction
<!-- eval-001: #22 -->

**Findings:** #22 (arbitrary paths via `--chrome-user-data-dir`)
**Files:** `src/cli.ts`, `src/chrome-cookies.ts`, `src/browsers.ts`
**Risk:** Medium — user can be tricked into reading cookies from non-browser apps
**Upstream delta:** Major structural changes:
- `detectChromeUserDataDir()` removed from `config.ts`, replaced by `browsers.ts` registry.
- `--browser <name>` flag added — provides a controlled allowlist of known browsers.
- `--cookies <ct0> <auth_token>` flag added — bypasses path-based extraction entirely.
- `loadChromeSessionConfig()` now accepts `overrides: { browserId?: string }` and validates against the browser registry.
- The `--chrome-user-data-dir` flag still exists for advanced use but is now secondary to `--browser`.

#### What to do

1. **When `--chrome-user-data-dir` is used without `--browser`:** Import `browserUserDataDir` from `src/browsers.ts`. If the provided path does not match any known browser's resolved path for the current platform, **error** and require `--force`:
   ```
   Error: /tmp is not a known browser data directory.
   Supported browsers: chrome, chromium, brave, firefox
   Use --browser <name> instead, or --force to proceed with this path.
   ```
2. **Print the resolved path** to stderr before extraction (browser-agnostic message):
   ```
   Reading cookies from: ~/Library/Application Support/Google/Chrome/Default/Cookies
   ```
3. Verify the `Cookies` file exists at the resolved path before extraction (already done by `queryCookies` — just ensure the error message is clear).

> **Note:** The `--browser <name>` flag already validates against the `BROWSERS` registry in `browsers.ts`. The main remaining gap is the `--chrome-user-data-dir` escape hatch. The `--cookies` flag provides a safe alternative that doesn't touch the filesystem at all.

#### Acceptance criteria

- [ ] `ft sync --chrome-user-data-dir /tmp` errors (not warns) with a helpful message
- [ ] `ft sync --chrome-user-data-dir /tmp --force` proceeds (and fails on missing Cookies file)
- [ ] `ft sync --browser chrome` works normally (already validated by registry)
- [ ] `ft sync --cookies <ct0> <auth>` works normally (no path validation needed)
- [ ] Resolved cookie DB path printed to stderr before extraction

#### Test approach

```bash
ft sync --chrome-user-data-dir /tmp        # should error
ft sync --chrome-user-data-dir /tmp --force # should proceed (fail on missing Cookies)
ft sync --browser chrome                     # should work, print resolved path
```

---

## Phase 2 — Low / Hardening

### T09 · Remove CWD from env file search paths
<!-- eval-001: #7 -->

**Findings:** #7 (CWD env injection)
**Files:** `src/config.ts`
**Risk:** Low-Medium — malicious `.env.local` in untrusted directories
**Upstream delta:** `loadEnv()` in `config.ts` still has CWD entries. Still fully open.

#### What to do

1. Remove the CWD entries from `candidatePaths` in `loadEnv()`:
   ```typescript
   const candidatePaths = [
     path.join(dir, '.env.local'),
     path.join(dir, '.env'),
   ];
   ```
2. If backward compatibility is needed, gate CWD loading behind an explicit env var:
   ```typescript
   if (process.env.FT_LOAD_CWD_ENV === '1') {
     candidatePaths.unshift(
       path.join(process.cwd(), '.env.local'),
       path.join(process.cwd(), '.env'),
     );
   }
   ```

#### Acceptance criteria

- [ ] `ft sync` in a directory with a malicious `.env` does NOT load it
- [ ] `~/.ft-bookmarks/.env` still loads
- [ ] Existing tests pass

#### Test approach

```bash
cd /tmp && echo "FT_CHROME_USER_DATA_DIR=/evil" > .env.local
cd /tmp && ft path  # should NOT pick up the /evil override
```

---

### T10 · Strengthen prompt injection sanitization
<!-- eval-001: #5 -->

**Findings:** #5 (fragile regex defense)
**Files:** `src/bookmark-classify-llm.ts`
**Risk:** Low — output validation is already strong
**Upstream delta:** Engine detection refactored into `src/engine.ts`. `sanitizeBookmarkText()` is unchanged. `classifyWithLlm()` and `classifyDomainsWithLlm()` now require `engine: ResolvedEngine` in options instead of auto-detecting. The function body is otherwise unchanged.
**Note:** Prompt injection patterns are unbounded — the regex list will always be incomplete. The primary defense is the output validation (JSON parse, ID allowlist, string filtering), which is already solid. The expanded regexes below are defense-in-depth; the code comment documenting this strategy is the most important part of the task.

#### What to do

1. Expand `sanitizeBookmarkText()` with additional patterns:
   ```typescript
   function sanitizeBookmarkText(text: string): string {
     return text
       .replace(/ignore\s+(previous|above|all)\s+instructions?/gi, '[filtered]')
       .replace(/you\s+are\s+now\s+/gi, '[filtered]')
       .replace(/system\s*:\s*/gi, '[filtered]')
       .replace(/<\/?tweet_text>/gi, '')
       .replace(/forget\s+(everything|all|previous)/gi, '[filtered]')
       .replace(/new\s+role\s*:/gi, '[filtered]')
       .replace(/\bact\s+as\b/gi, '[filtered]')
       .replace(/\bpretend\s+(you|to)\b/gi, '[filtered]')
       .replace(/[\u200B-\u200F\u2028-\u202F\uFEFF]/g, '') // zero-width chars
       .slice(0, 300);
   }
   ```
2. Add a comment documenting that output validation (JSON parse, ID allowlist, string filtering) is the primary defense; input sanitization is defense-in-depth.

#### Acceptance criteria

- [ ] "forget everything" → `[filtered]`
- [ ] "new role:" → `[filtered]`
- [ ] Zero-width characters stripped
- [ ] Existing classification still works (run `ft classify` on a test DB)
- [ ] Comment documents the defense-in-depth strategy

#### Test approach

Unit test: pass known injection payloads through `sanitizeBookmarkText()`, assert they are filtered.

---

### T11 · SQLite database file permissions
<!-- eval-001: #3 -->

**Findings:** #3 (world-readable DB)
**Files:** `src/db.ts`
**Risk:** Low — directory perms `0o700` (T02, done upstream) provide primary protection, but defense-in-depth
**Upstream delta:** `saveDb()` now uses atomic `.tmp`+rename (upstream `5af58f7`), but still has no `mode: 0o600` on the write.

#### What to do

1. In `saveDb()`, add restricted permissions to the temp file write:
   ```typescript
   export function saveDb(db: Database, filePath: string): void {
     const dir = path.dirname(filePath);
     if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
     const data = db.export();
     const tmp = filePath + '.tmp';
     fs.writeFileSync(tmp, Buffer.from(data), { mode: 0o600 });
     fs.renameSync(tmp, filePath);
   }
   ```

#### Acceptance criteria

- [ ] `bookmarks.db` created with `0o600`
- [ ] `ft index` and `ft classify` still work
- [ ] `stat` on DB file confirms restricted perms

#### Test approach

```bash
rm ~/.ft-bookmarks/bookmarks.db && ft index
stat -c "%a" ~/.ft-bookmarks/bookmarks.db  # Linux
# macOS: stat -f "%Lp" ~/.ft-bookmarks/bookmarks.db
# Expected: 600
```

---

### T12 · Media file permissions
<!-- eval-001: #3 -->

**Findings:** #3 (world-readable media files)
**Files:** `src/bookmark-media.ts`
**Risk:** Low — directory perms `0o700` (T02, done upstream) provide primary protection, but defense-in-depth
**Upstream delta:** No changes to this file. Still fully open.

#### What to do

1. In `fetchBookmarkMediaBatch()`, add restricted permissions to the `writeFile` call (~line 170):
   ```typescript
   await writeFile(localPath, buffer, { mode: 0o600 });
   ```

#### Acceptance criteria

- [ ] Downloaded media files created with `0o600`
- [ ] `ft fetch-media` still works end-to-end
- [ ] Manifest file (`media-manifest.json`) also `0o600` (covered by T03 if it lands)

#### Test approach

```bash
ft fetch-media --limit 1
stat -c "%a" ~/.ft-bookmarks/media/*  # Linux
# macOS: stat -f "%Lp" ~/.ft-bookmarks/media/*
# Expected: 600 for all files
```

---

## New findings from upstream (not in eval-001)

### N01 · Direct `writeFileSync` calls bypass `fs.ts` permission defaults
**Files:** `src/cli.ts` (lines 149, 178, 452), `src/preferences.ts` (line 17)
**Risk:** Low — all contain non-sensitive metadata

Several locations use `fs.writeFileSync` directly instead of `writeJson()` from `fs.ts`, so they won't benefit from T03's default `0o600` mode:

| File | Line | What | Contains |
|------|------|------|----------|
| `cli.ts` | ~149 | `.update-check` | Latest version string |
| `cli.ts` | ~178 | `.last-version` | Current version string |
| `cli.ts` | ~452 | `gaps-failures.json` | Bookmark IDs + failure reasons |
| `preferences.ts` | ~17 | `.preferences` | Default engine name |

**Recommendation:** Fold into T03 scope — migrate direct `writeFileSync` calls to use `writeJson()` from `fs.ts`, or add `{ mode: 0o600 }` explicitly to each. Lowest priority among the file-perm tasks.

---

## Task Status Tracker

| Task | Phase | Status | Upstream Impact | Finding(s) |
|------|-------|--------|-----------------|------------|
| ~~T02~~ | ~~P0~~ | ✅ Done | Fully addressed by `5af58f7` | #3 |
| T01 | P0 | ⬜ Open | New: `firefox-cookies.ts` temp copies; SIGINT conflict with `createSpinner` | #1, #23 |
| T03 | P0 | ⬜ Open | Reduced: upstream added `WriteOptions.mode` but defaults to umask | #3, #24 |
| T04 | P0 | ⬜ Open | Rewritten: new `--cookies`/`--browser` flags change scope | #1 |
| T05 | P1 | ⬜ Open | No upstream changes | #4 |
| T06 | P1 | ⬜ Open | No functional changes; line refs updated | #6 |
| T07 | P1 | ⬜ Open | Reduced: remove redundant chmod only | #25 |
| T08 | P1 | ⬜ Open | Rewritten: `browsers.ts` registry replaces `detectChromeUserDataDir()` | #22 |
| T09 | P2 | ⬜ Open | No upstream changes | #7 |
| T10 | P2 | ⬜ Open | Engine refactored to `engine.ts`; sanitization unchanged | #5 |
| T11 | P2 | ⬜ Open | Reduced: atomic write added, just needs `mode: 0o600` | #3 |
| T12 | P2 | ⬜ Open | No upstream changes | #3 |

---

## Findings NOT tasked (by design)

These eval-001 findings are informational, by-design, or not actionable as code changes:

| # | Finding | Reason not tasked |
|---|---------|-------------------|
| 2 | ~~Cookies in CLI args~~ | False positive (v1.2) |
| 8 | Hardcoded bearer token | By design — public token, no alternative |
| 9 | UA spoofing | By design — required for GraphQL endpoint |
| 10 | No data integrity | Over-engineering for local-first CLI |
| 11 | GraphQL query ID fragility | Operational risk, not a code fix |
| 12 | Plaintext PII | By design — "self-custody" model |
| 13 | No secure delete | Low risk; SQLite VACUUM is opt-in |
| 14 | Error messages leak paths | Acceptable for CLI tool |
| 15 | Dependency supply chain | CI/CD concern, not a code change |
| 19 | FTS5 syntax abuse | Local-only, intentional power-user feature |
| 20 | execFileSync PATH trust | Pre-compromise scenario |
| 21 | LIKE pattern injection | Local-only, read operation |

---

## Reviewer Notes

### v1.3 — Upstream re-baseline

All 12 tasks re-verified against `upstream/main` @ `83265d0`. Key findings:

- **T02 closed:** Upstream `5af58f7` added `mode: 0o700` to `ensureDirSync()`.
- **T03 scope reduced:** Upstream added `WriteOptions.mode` opt-in parameter and atomic writes, but didn't make `0o600` the default. The task now focuses on changing the default.
- **T07 scope reduced:** Upstream already passes `{ mode: 0o600 }` to `writeJson` in `xauth.ts`. Task is now just removing the redundant `chmod`.
- **T04 rewritten:** Upstream added `--cookies` (bypasses extraction entirely) and `--browser` (validated registry). Consent prompt now needs to account for these alternatives.
- **T08 rewritten:** `detectChromeUserDataDir()` removed. `browsers.ts` provides a validated registry. Task now focuses on the `--chrome-user-data-dir` escape hatch.
- **T01 SIGINT conflict:** `createSpinner` in `cli.ts` uses `process.once('SIGINT', ...)` which consumes the first SIGINT. Recommended `prependListener` to avoid conflict.
- **New file `firefox-cookies.ts`:** Has the same temp copy pattern as `chrome-cookies.ts` and needs the same `0o600` fix.

### v1.1 — Original source verification (retained for reference)

#### ✅ Resolved (v1.1)

- **T01 Node API bug** — Fixed in v1.2 (single-call `writeFileSync(path, data, { mode })`).
- **T03/T07 dependency** — Confirmed: `xauth.ts` calls `writeJson()` from `fs.ts`.
- **T04 `isFirstRun()` semantics** — Checks `!existsSync(cachePath)`, not data dir.
- **T06 server location** — Inside Promise constructor, both `timer` and `server` in scope.
- **T08 known paths** — Now in `browsers.ts` registry (v1.3 update).

#### ✅ Clarifications resolved

- **T01 signal handler** — Resolved in v1.3: use `prependListener` to avoid conflict with `createSpinner`.
- **T08 warn vs error** — Resolved in v1.2: upgraded to error + `--force`.

#### 📋 Observations (v1.1, still relevant)

- **Duplicate `ensureDir`** — `paths.ts:ensureDirSync()` (sync) and `fs.ts:ensureDir()` (async) both needed `0o700`. T02 (now closed) fixed the sync version. T03 still needs to fix the async version.
- **Cross-platform test commands** — Several test approaches use macOS `stat -f "%Lp"`. Where applicable, Linux alternatives (`stat -c "%a"`) are now noted.
- **Line number references** — All marked as approximate with `~` prefix. These drift as changes land.
