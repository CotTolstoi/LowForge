# LowForge (v1.4.0-dev)

A Python orchestrator for autonomous and semi-autonomous software development through OpenAI-compatible APIs, with a local web interface (port `8876`).

## Quick Start (Windows)

* Requirements: Python 3.10+ and an OpenAI-compatible provider API key.
* Start: run `START.bat` (the local dashboard opens at `http://127.0.0.1:8876`).

## Latest Results · November 17, 2026

### Small Project · Orderbook Engine

GPT-6 Luna, `reasoning: none`. All harnesses used the same initial codebase and completed three sequential phases. LowForge and Codex CLI took part in a paired run. Aider, Claude Code, and OpenCode ran in a separate series with the same task and reasoning mode.

| Harness | Score | Phases passed | Time (s) | API requests | Input tokens | Output tokens |
|---|---:|---:|---:|---:|---:|---:|
| LowForge-v1.4 | 60/68 | 0/3 | 108.1 | 9 | 48,198 | 4,305 |
| Aider | 57/68 | 0/3 | 251.0 | 3 | 18,182 | 11,546 |
| Claude Code | 56/68 | 0/3 | 232.1 | 46 | 303,956 | 5,952 |
| OpenCode | 55/68 | 0/3 | 201.7 | 30 | 275,533 | 6,357 |
| Codex CLI | 52/68 | 0/3 | 318.2 | 82 | 1,284,946 | 8,382 |

The score sums checks across the three phases (17 + 24 + 27), including repeated checks. A phase passes only when all its checks pass and the harness completes successfully. LowForge's final phase was interrupted by `HTTP 400 invalid_prompt`. The scorer evaluated the saved result for that phase at 21/27.

### Large Project · Enterprise ERP Suite

GPT-6 Luna, reasoning `low`. A 24-module Python repository with 3,093 lines of code and three sequential phases. The time in the table is the sum of harness execution time across phases.

| Harness | Phases passed | Score | Wall time (s) | Requests | Tool calls | Input tokens | Output tokens | Max input/request | Files modified / 24 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| LowForge-v1.4 | 0/3 | 40/60 | 245.4 | 21 | 0 | 263440 | 10607 | 30594 | 7/24 |
| Claude Code | 0/3 | 33/60 | 94.2 | 20 | 33 | 178442 | 3381 | 19291 | 4/24 |
| Aider | 1/3 | 37/60 | 188.2 | 7 | 0 | 143811 | 7238 | 28076 | 2/24 |

Claude Code version 2.1.304 and Aider version 0.86.2 were used. The score out of 60 sums checks across the three phases (10 + 20 + 30); some checks are repeated. A phase passes only if all its checks pass.

## How These Results Were Obtained

LowForge uses Python for orchestration, a local web interface, and an OpenAI-compatible API for model calls. During a run, it selects repository context within a budget, applies edits, and runs checks. In the benchmarks, an independent scorer evaluated the result in Docker with networking disabled. This made it possible to assess the application's behavior separately, even when LowForge's own verification was limited to compilation.

In the ERP benchmark, LowForge achieved the highest total score (40/60) and modified 7 of 24 files. Aider was the only harness to pass an entire phase (10/10) and used the fewest requests (7). Claude Code had the shortest total phase time (94.2 s). These differences were measured in one run per harness. Tool-call counters differ between harnesses, and the number of modified files indicates the extent of edits. No exact matches between captured LowForge requests and complete file contents were found; this is consistent with snippets being sent.

Between the Orderbook and ERP runs, one retry with a corrected request body was added to the **benchmark gateway** for `HTTP 400 invalid_prompt` responses when sanitization changes the body. No API errors were recorded in the valid ERP phases. The contribution of individual mechanisms to the scores would require controlled repeat runs.

## Detailed Reports on Recent Benchmarks

### Small Projects · Autonomous Runs and Codex Recovery

Helpdesk and Workshop passed the base phase and upgrade phase with LowForge. In Stockroom, the base phase passed, but the upgrade returned HTTP 400 when archiving an active record instead of the expected HTTP 409. Known aggregate LowForge usage was 127,827 input tokens and 29,204 output tokens.

The initial Codex CLI run and two separate recovery runs produced 2 successful phase attempts out of 11, including retries. The Helpdesk and Stockroom base phases passed after recovery. Recorded failures included a missing `app.py`, session-completion errors, and an incorrect HTTP status in Workshop. Aggregate Codex CLI usage, including retries, was 1,578,398 input tokens and 49,755 output tokens. In Assisted runs, three repair attempts yielded no accepted core changes, so the LowForge Assisted phases have no results.

### Orderbook Engine · Three Phases and Two Reasoning Levels

| Reasoning | Harness | Base | Upgrade concurrency | Refactor audit | Total score | Wall time (s) | Requests | Input tokens | Output tokens |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| none | LowForge-v1.4 | FAIL 16/17 | FAIL 23/24 | FAIL 21/27 (harness failed) | 60/68 | 108.1 | 9 | 48198 | 4305 |
| none | Codex CLI | FAIL 14/17 | FAIL 20/24 | FAIL 18/27 | 52/68 | 318.2 | 82 | 1284946 | 8382 |
| xhigh | LowForge-v1.4 | PASS 17/17 | PASS 24/24 | PASS 27/27 | 68/68 | 810.4 | 11 | 88419 | 42874 |
| xhigh | Codex CLI | FAIL 17/17 (harness failed) | PASS 24/24 | FAIL 22/27 | 63/68 | 1957.2 | 120 | 2318828 | 78065 |

In `none` mode, the provider returned `HTTP 400 invalid_prompt` during LowForge's final phase. The scorer also recorded failed checks. In `xhigh` mode, LowForge completed all three phases and scored 68/68. Codex CLI scored 17/17 in the base phase but exhausted the 60-request limit and ended that phase with FAIL status. In a separate `xhigh` run, Claude Code scored 68/68, while Aider was interrupted during the base phase before the scorer ran.

### Enterprise ERP Suite · Results by Phase

| Harness | Phase | Score | Status | Wall time (s) | API requests | Tool calls | Input | Output | Max input/request | Modified / 24 |
|---|---|---:|---|---:|---:|---:|---:|---:|---:|---:|
| LowForge-v1.4 | multi_warehouse_allocation | 9/10 | FAIL | 116.9 | 14 | 0 | 159011 | 4775 | 21028 | 4/24 |
| LowForge-v1.4 | tiered_tax_and_credit_hold | 14/20 | FAIL | 69.4 | 3 | 0 | 36385 | 3329 | 29723 | 6/24 |
| LowForge-v1.4 | credit_note_reversal_and_audit | 17/30 | FAIL | 59.1 | 4 | 0 | 68044 | 2503 | 30594 | 0/24 |
| Claude Code | multi_warehouse_allocation | 8/10 | FAIL | 33.6 | 8 | 12 | 46728 | 1136 | 10510 | 2/24 |
| Claude Code | tiered_tax_and_credit_hold | 10/20 | FAIL | 8.5 | 2 | 9 | 2903 | 255 | 1871 | 0/24 |
| Claude Code | credit_note_reversal_and_audit | 15/30 | FAIL | 52.1 | 10 | 12 | 128811 | 1990 | 19291 | 3/24 |
| Aider | multi_warehouse_allocation | 10/10 | PASS | 103.8 | 2 | 0 | 24111 | 4786 | 13748 | 2/24 |
| Aider | tiered_tax_and_credit_hold | 12/20 | FAIL | 51.6 | 3 | 0 | 68595 | 1439 | 26144 | 0/24 |
| Aider | credit_note_reversal_and_audit | 15/30 | FAIL | 32.8 | 2 | 0 | 51105 | 1013 | 28076 | 0/24 |

- **Multi-warehouse allocation.** LowForge scored 9/10. The failed check required the API to expose both available and reserved stock.
- **Taxes and credit limits.** LowForge scored 14/20. Failures covered accounting for unpaid invoices and reserved orders, side effects of placing a credit hold, and atomicity when releasing a hold.
- **Refunds and audit.** LowForge scored 17/30 and ended with failed status without making new changes to files in this phase. Failed checks included restocking the original batch, proportional tax adjustments, compensating ledger entries, idempotency, and audit hash-chain verification.
- **Run recovery.** LowForge phases 2–3 resumed from a saved snapshot after a runner collision in phase 1. Aider's three initial attempts without access to the task files were excluded from scoring. An independent Docker scorer evaluated all nine valid phases.

ERP benchmark settings: 128,000-token context, up to 16,384 output tokens, up to 60 requests per phase, 1,500-second phase timeouts, and 180-second HTTP timeouts. The benchmark used 2,160 of the 90,000-unit upper cap.
