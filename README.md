# final_code_check — Pre-Release Test + Review Suite for AI-Written Code

[中文文档](#中文) | English

> Ship AI-written code with confidence. An opinionated, evidence-driven pre-release checklist and workflow — battle-tested on production SaaS (Vue3 + FastAPI, multi-tenant), covering everything from unit tests to live penetration testing.

## Why

AI coding agents write code fast — and break things in ways manual review misses:

- Fix one bug, break three other pages (shared CSS / shared components / silent refactors)
- Tests that look green but mock away the very logic they should verify
- "Done" claims that were never actually run
- Cross-tenant data leaks that pass every unit test

`final_code_check` is a **discipline, not a linter**: a curated set of 8 review surfaces + a live penetration-testing layer, distilled from real production incidents, mapped to ISO/IEC 25010, OWASP ASVS v4, and Release Readiness checklists.

## What makes it different

| Typical review tools | final_code_check |
|---|---|
| Static analysis, reads code | **Live testing**: real JWT tampering, real IDOR with two accounts, real injection payloads against your running app |
| Trusts "tests passed" | **Anti-fake-green**: audits the tests themselves (13 success-masquerading patterns) |
| Trusts the reviewer | **Canary self-check**: deliberately plant known defects to measure your reviewer's recall |
| One fix at a time | **Fix-one-break-none**: impact map for shared resources + repo-wide same-pattern sweep |
| Generic | **Per-project config** (`references/<project>.md`): SSH, containers, commands, compliance red-lines — zero project coupling in the core |

## Coverage

**Testing surfaces (T1–T4)**
- T1 Test suite execution — unit tests + API smoke + regression + **impact map** (grep every reference of shared resources before touching them) + **same-pattern repo sweep** (found one `err.message` leak? find them all)
- T2 Deep testing — E2E user journeys, performance/queue load, fault injection, data migration, restart drills
- T3 Anti-fake-green — tests must assert real behavior; **13 success-masquerading patterns** (lint-as-testing, mock-the-core, happy-path-only, "should work" wording, agent self-report as acceptance...)
- T4 Security testing — SQLi / XSS / command injection / path traversal / IDOR / upload validation, all with live payloads

**Review surfaces (1–7)**
- Auth routes, IDOR, SSE/long-connection lifecycle, error-message leakage
- Injection & command execution, secrets scanning, dependency CVEs
- Frontend JS/CSS (inline script syntax, dangerous APIs, tag balance, cache busting)
- Production consistency (git ↔ container ↔ host md5 three-way drift check)
- Compliance & data isolation (industry red-lines: no financial advice, no legal advice, disclaimer wording)
- Ops depth: credentials, backups + restore drill, rollback path, kill-switch for features

**Penetration layer (P1–P5)** — the differentiator
- P1 Auth/session: JWT tampering 4-ways (`alg:none`, fake HS256, garbage, none), brute-force lockout, CSRF form-post
- P2 IDOR: **two real accounts**, A creates resources, B attacks read/update/delete — must be 404, never 200
- P3 Injection: stored-XSS round-trip, SQLi, path traversal, **prompt injection against LLM apps, MCP tool-abuse attempts**
- P4 Scanning: nikto + pip-audit + Trivy, CVE triage against actual usage (not scanner FUD)
- P5 Info leakage: admin surface fail-closed, robots.txt, error echoes, backup files

## The canary check (reviewer quality control)

Before dispatching a review, plant 1–2 known defects (e.g. an obvious unauthenticated route, a raw `innerHTML` insertion) into the review material. After review:

- Reviewer caught them → this review round is trustworthy
- Reviewer missed them → the review is performative; re-dispatch or change strategy

Canary defects use unique markers (`# canary-defect-<id>`) and are **removed before shipping**. Never merge them.

## Anti "fix one, break another" loop

Three root causes of fix-induced regressions, three gates:

1. **No root cause → no patch.** Build a reproducible red→green loop first (systematic-debugging)
2. **Minimal diff only.** If the diff can't be explained in one sentence, it's too big
3. **Every bug fix ships with a regression test** — a fix without one fails review

Then: re-run the full suite against the recorded baseline, and re-test every point on the impact map. **Three consecutive failed fixes = stop and question the architecture**, not a fourth patch.

## Usage

### With an AI agent

Say: `run final_code_check` / `pre-release check` / `security review + code review`

Or follow the workflow manually:

```
0. Build references/<project>.md (SSH, paths, containers, test commands, health check, red-lines)
   — keep it local, .gitignore it, never commit real IPs/keys
0.5 Read audit baseline + git diff/AST → incremental skip decision + detect stage S1–S4 → trim check set
1. Env verification — git/container/host three-way consistency
2. T1 test suite — unit + API smoke + regression + impact map
3. Independent code-review subagent — fail-closed (optional: add canary defects)
4. Security sweep — injection / IDOR / upload / secrets
5. Penetration layer — P1 auth + P2 IDOR + P3 injection required; P4 + P5 by risk
6. Frontend validation / dependency audit
7. Compliance red-lines + data isolation + doc-drift check
8. Final gate — clean git status, md5 aligned, tests green, probe data cleaned up
9. Second-line verification L1→L2→L3 — process integrity → reproduction/sampling/canary → evidence
   package signing; produces TRUSTED / SUSPICIOUS / UNTRUSTED verdict
10. Self-evolution retrospective — patch the skill in place for new defect patterns; rule-pack version +1
```

### Incremental audits + stage-aware dispatch (v1.1)

- **AST-based incremental skip**: comment/whitespace/format-only changes never trigger a re-audit; function-level change detection reuses last audit verdicts for untouched units
- **S1–S4 stage auto-trimming**: prototype / feature-complete / pre-merge / release-gate — the matching T/P subset is selected automatically, no full pen-test spam on prototypes
- **False-positive suppression**: code-marker waivers (with expiry), context-aware downgrade (escHtml wrapper detected → alert, not vulnerability), subagent three-way output (confirmed / suspect / false_positive) + false-positive knowledge base
- **Second-line verification L1–L3**: process integrity (no silent failures, no missed scan targets) → result reproduction (confirmed findings 100% reproduced, pass-unit blind sampling 5–30% by stage) → sha256-signed evidence package; emits TRUSTED / SUSPICIOUS / UNTRUSTED gate verdicts
- **Self-evolution**: every audit round ends with a retrospective; new defect patterns patch the skill in place, rule-pack version +1 recorded in the baseline snapshot

**Incremental engine**: `python3 scripts/fcc_incremental.py plan --repo <dir>` produces the four-state decision + stage-trimmed check set; `verify --finalize` runs the L1→L2→L3 gate; `selftest` runs 17 built-in checks.

### Standalone frontend checker

```bash
python3 scripts/fe_check.py <html-root> --check-js --check-tags
# Reports: inline JS syntax failures / dangerous APIs (eval, document.write…) /
#          tag imbalance /疑似 hardcoded secrets
```

### Scope trimming

| Project type | Run |
|---|---|
| Backend-only API | T1 + reviews 1/2/3 + P1 P2 P4 |
| Static frontend | T1 + frontend validation + cache check |
| Docker deployment | + production consistency + Trivy |
| Auth / upload features | T4 + P1 P2 P3 **mandatory** |
| LLM / Agent apps | + prompt injection + MCP tool-abuse testing |
| "Most strict" request | Everything, no trimming |

## Mapping to industry standards

- **ISO/IEC 25010** (8 quality characteristics) — every dimension covered, see SKILL.md §4.1
- **OWASP ASVS v4** — V1 architecture, V2/V3 auth & sessions, V4 access control, V5 input validation, V7 errors, V8 logging, V9 data protection, V11 file/business logic, V12–14 APIs
- **Release Readiness Checklist** — code, tests, deployment, ops, release claims

## Contributing

- Issues: report problems or suggest new checks (describe your scenario + expected behavior)
- PRs: welcome; each change is reviewed before merge
- Fork freely for private use — but **never commit your real `references/` (IPs, SSH, keys)**

## License

MIT
