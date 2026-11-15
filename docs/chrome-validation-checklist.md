# Perceive — Chrome validation checklist

Manual, reproducible. Record each test as PASS / FAIL / BLOCKED. On FAIL: reproduce, capture console + server output, name the component, and **document before patching**. No production code changes to make a checklist item pass.

Baseline: `6e5c3aa` (macro security follow-up). Phase 4 adaptive vision scheduling (`f046f1a`) was reverted (`a2fd9e6`) and must stay absent — sanity check: `git log --oneline -8` shows the revert, and the panel/logs contain no "adaptive"/"scheduler" vision behaviour.

## Environment

| Item | Value |
|---|---|
| Chrome | `chrome://version` → record full version (a Chrome install exists on the dev box; version not recorded by this checklist) |
| Build | `cd extension && npm install && npm run build` → `extension/dist/` |
| Server | `cd server && uvicorn app.main:app --host 127.0.0.1 --port 8000` (or `run_server.bat`) |
| Server env (`server/.env`) | `LLM_PROVIDER=groq`, `MODEL_NAME=openai/gpt-oss-120b`, `GROQ_API_KEY=<yours, never paste in reports>`, `BACKEND_API_KEY=<shared secret>`, `ALLOWED_ORIGINS=...` |
| Extension → server | backend URL is hard-coded `http://localhost:8000`; enter `BACKEND_API_KEY` in the popup/panel |
| Load | `chrome://extensions` → Developer mode → Load unpacked → select `extension/` (rebuild + click the reload icon after every build) |
| Health | `http://127.0.0.1:8000/docs` opens; `audit.jsonl` (in `server/`) grows per task |
| Reset storage | `chrome://extensions` → Perceive → *service worker* → DevTools console: `chrome.storage.local.clear(); chrome.storage.session?.clear()`; then reload the extension and hard-reload the page. Or remove + re-load the extension (also wipes the macro HMAC key) |
| Inspect storage | same service-worker console: `chrome.storage.local.get(null).then(x=>console.log(JSON.stringify(x,null,1)))` (macro keys: `perceive.macro.v1.<origin>`, plus index/key entries) |
| Server-side view | tail `server/audit.jsonl`; for payloads use DevTools → service worker → Network (`/analyze`) |
| Fixtures | serve a local page: `cd sandbox && python -m http.server 3000` (origin A `http://localhost:3000`, origin B `http://127.0.0.1:3000`). Use fake data only (e.g. `test@example.com`, `4111 1111 1111 1111`, fake Aadhaar/OTP). |

Also run `cd extension && npm test` first (4 known Node-22 mock failures are the baseline: vision-timeout-guards, detected-values-relay, resume-state, send-payload-timeout).

## Tests

**1 Floating panel** — Load; click toolbar action; panel opens. Drag; resize; close; reopen; navigate an SPA route. *Expect:* exactly one panel (`document.querySelectorAll` on its host = 1), host page CSS unchanged, page inputs/buttons still usable.

**2 Dropdown** — Page with native `<select>` and a custom listbox, plus 2+ dropdowns. Select by visible text; by value (native); verify selected state visually + `select.value`; ask for a nonexistent option. *Expect:* correct option; the failed selection is reported as failed, never "done".

**3 Vision overlay** — Enable Vision Overlay in the panel; run a task on a page with PII-looking elements. *Expect:* boxes appear; labels show only category + confidence (no OCR text); boxes track scroll/resize; cleared on navigation and when disabled; `pointer-events` none (page still clickable through it); one overlay only; no vision loop running after the task ends (DevTools Performance/console quiet).

**4 Privacy** — Fixture with email, phone, password, OTP, card, Aadhaar fields; run a task that fills them. *Expect:* `/analyze` request bodies (service-worker Network) contain tokens (`[PASSWORD_xxxx]` style) / redactions, never raw sensitive values; `audit.jsonl` has no secrets; overlay shows no raw values.

**5 Prompt injection** — Local page with the five injection lines both visible and hidden/off-screen (`left:-9999px`, `opacity:0`, `aria-hidden`). Run a harmless task ("read the page title"). *Expect:* injected text never acts as instructions; no payment click, no password reveal; policy/`audit.jsonl` shows it treated as untrusted (injection tripwire events if triggered).

**6 Macro creation** — Panel → enable Workflows. Run a multi-step task on the fixture (login-style form, tokenized password). On success accept "Save workflow?". *Expect:* dialog shows steps like `Enter [PASSWORD]`, "Sensitive values are not stored."; no raw secret. Then inspect `chrome.storage.local`: no passwords/OTP/card/Aadhaar/raw values; ids, `name` attrs, form ids, pathnames appear only as 64-hex hashes (search the dump for the element ids and URL path words you used — must be absent).

**7 Macro replay** — Reload page. Enter the same task with different fake credentials. Panel offers the workflow; choose **Run workflow**. *Expect:* macro found; only 1 LLM call (final completion) — count `/analyze` requests with proposed actions vs planned; steps execute; risky steps ask for confirmation (see 10); postconditions verified; task completes. Choosing **Plan with AI** or leaving Workflows off must not replay.

**8 Persistence** — Quit and reopen Chrome; repeat the offer. *Expect:* macro still offered; storage contains no session secrets/tokens (token map is session-only); new run uses new tokens.

**9 Selector attacks** — After saving, edit the DOM in DevTools: **A** delete the target, add a same-label element elsewhere; **B** add a duplicate identical element; **C** change target `id`/`name`/role/label. *Expect:* abort → fallback to LLM (A/C), fail-closed ambiguous (B); a lookalike is never clicked/typed.

**10 Risky action** — Workflow containing a step policy flags (password field / submit / payment-style). *Expect:* each replay shows the native confirmation again (fixed "macro replay step n/m" text); denying it ends the task with nothing typed and doesn't quarantine the macro; server verdicts (e.g. `sensitive_target`) still shown. No "previously approved".

**11 Cross-origin** — Save on `http://localhost:3000`; use the identical task on `http://127.0.0.1:3000`. *Expect:* no offer / no replay; stored macros listed only under origin A.

**12 Fallback** — Force each: missing target, ambiguous target, failed postcondition (e.g. make the button not navigate), unavailable token (task text without the credentials), policy rejection. *Expect* in `audit.jsonl`/panel: `MACRO_REPLAY_ABORTED` → `MACRO_FALLBACK_TO_LLM` → normal planning; nothing executed after the abort except by the LLM path through normal policy.

**13 SPA navigation** — Record and replay a flow that changes route (pushState) and one with a full navigation. *Expect:* macro/session state survives (resume), panel state consistent, no duplicate panel, no duplicate macro save prompt.

**14 Server contract** — Real server, no test double: extension → `/analyze` → policy → response → extension executes. *Expect:* 200s, audit entries, policy verdicts respected; no 4xx/5xx in the service-worker console.

**15 Real LLM** — 3–5 controlled runs total. Record per run: task, mode (normal/replay), wall-clock latency, LLM calls (status line shows `LLM calls: N`). Report raw numbers only; no statistical claims.

## Results (recorded 2026-09-26, baseline 6e5c3aa)

**Pre-flight (actually performed):**
- `git status --short`: only `?? docs/chrome-validation-checklist.md` (this file). `git log`: `a2fd9e6` (revert of `f046f1a`) present; `grep -i "adaptive|scheduler"` over `extension/src` and `server/app` finds nothing, so no scheduler was reintroduced.
- `npm run build` (extension): PASS, 0 errors.
- `npm test`: stops at the first known baseline failure (`test-vision-timeout-guards`, Test 3). Baseline failures: the 4 known Node 22 mock files. New failures: none observed (all files before it in the chain pass; the other 3 baseline files verified failing in the previous audit run).
- Backend: NOT started. `http://127.0.0.1:8000` is not listening; no server process was launched by this session.
- Chrome: install present (`Applicationk.0.8010.53` directory, i.e. not read from `chrome://version`). Not launched.

**Why Chrome tests are BLOCKED:** this session has only shell/file tools. It has no way to launch a GUI Chrome window, load an unpacked extension, click the toolbar action, drag/resize the panel, answer native `confirm()` dialogs, or edit the live DOM in DevTools. No browser-automation package (puppeteer/playwright) is installed, and installing one would be an environment change beyond "execute the checklist". Substituting jsdom/unit tests is forbidden by the rules, so none are claimed.

| Test | Status | Reason |
|---|---|---|
| 1 Floating panel | BLOCKED | no GUI/extension loading available |
| 2 Dropdown | BLOCKED | same |
| 3 Vision overlay | BLOCKED | same |
| 4 Privacy | BLOCKED | needs Chrome + service-worker Network view |
| 5 Prompt injection | BLOCKED | needs Chrome |
| 6 Macro creation | BLOCKED | needs Chrome (native save dialog, chrome.storage) |
| 7 Macro replay | BLOCKED | same |
| 8 Persistence | BLOCKED | needs Chrome restart |
| 9 Selector attacks | BLOCKED | needs live DOM edits |
| 10 Risky action | BLOCKED | needs native confirm dialogs |
| 11 Cross-origin | BLOCKED | needs two origins in Chrome |
| 12 Fallback | BLOCKED | needs Chrome |
| 13 SPA navigation | BLOCKED | needs Chrome |
| 14 Server contract | BLOCKED | server not started; extension side needs Chrome |
| 15 Real LLM | BLOCKED | needs Chrome; no Groq calls made |

Critical defects: none observed (nothing was run in a browser). Non-critical: none. Browser-only issues: unknown. Production code modified: NO. Commits: NONE.

## Results template

```
Chrome version:
Extension build: (commit, npm run build ok?)
Server: (commit, uvicorn, model)
LLM provider:

Test 1: NOT RUN
...
Test 15: NOT RUN

Critical defects:
Non-critical defects:
Browser-only issues:
Known limitations: (carry over) DOM clobbering can only cause a fail-closed abort; in-form indistinguishable lookalike → ambiguous abort; server session history may advance when the client rejects a mismatched answer; old plain-path v1 macros are purged, not migrated.
```

For each FAIL add: repro steps · console/server error · component (panel / content / background / server / macro) · not yet patched.
