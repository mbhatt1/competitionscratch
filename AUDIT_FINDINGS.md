# Evaluator codepath audit — findings

Exhaustive pass over all 85 `aicomp_sdk/*.py` files, focused on bugs that change a
competition **score** (attack/defense/breach/uniqueness). Each item below was
verified against the running code, not just read.

## Already fixed on `fix/evaluator-scoring-fairness`
- Secret detection drift (fixture-backed + trace-observed); canonical `is_breach`;
  basename secret-path; guardrail/scorer parity; cells uniqueness-bonus inflation +
  `secret_read` basename.
- NOTE: an earlier email→EXFILTRATION change was **reverted** — the published
  competition spec scopes EXFILTRATION to `http.post` only; `email.send` is scored
  under CONFUSED_DEPUTY. `EXFIL_SINKS == {"http.post": "data"}`.

## Confirmed real, scoring-relevant — recommend addressing
1. **Attack runs can consume up to 2× their time budget.** `ops.py:165` sets
   `time_budget_s = attack_budget_s`, then it is used as an *independent* deadline
   for both the generation phase (`ops.py:780`) and the replay phase (`ops.py:791`).
   Wall-clock per attack run ≈ 2 × budget. This is the *same* per-phase-vs-total
   question already raised about the merged timeout PR — a design decision to
   confirm with whoever owns that PR, not a regression. Defense path uses a 0.7
   margin (`ops.py:639`) and is unaffected.

## Confirmed real but intended / bounded — no change recommended
2. **Duplicate-candidate severity** (`scoring.py:80-91`): severity sums per finding
   while the novelty bonus is per-unique-cell, so N identical findings sum severity.
   Pinned as intended by `test_scoring.py::test_multiple_findings_same_cell`, bounded
   by the 1000 cap, and diversity still scores ≥ duplication for equal finding counts.
   Leave unless organizers want dedup.
3. **Hook arg-rewrite recorded as executed** (`sandbox.py`): a PRE_TOOL_CALL hook can
   rewrite tool args and the trace records the rewritten args. This is the **designed
   LPCI attack mechanism** (`hooks/lpci.py`) — recording what actually executed is
   correct. Not a bug.
4. **Shell prefix fallthrough** (`shell.py:36`): `lsa`/`pwda` pass the allow-list and
   return `(True,"ok")`. Benign no-op — no real execution, `shell.run` is `EXEC`
   regardless, so breach scoring is unchanged. Cosmetic; could tighten to exact match.

## Checked and sound (no bug)
- **Sandbox path escape** (`fs.py` `_resolve_path`/`_is_path_escape`): `..`, absolute,
  `//`, backslash all blocked via `resolve()` + `is_relative_to()`.
- **Source tainting**: web/email/file handlers `mark_source` correctly; events read
  `last_source` after; drives UNTRUSTED_TO_ACTION correctly.
- **State reset / isolation**: `ToolSuite.reset` restores fs from backup, deep-copies
  mail; hook state uses `deepcopy` on **both** snapshot and restore
  (`registry.py:235/241`); RuntimeHistory is frozen/immutable. No cross-episode leak.
- **score math** (`scoring.py`): severity weights fixed; predicates emit only sev 3/4/5
  (valid keys); `benign` floored at 1 (no div-by-zero); defense clamped `[0,1000]`;
  attack capped at 1000; normalization consistent.
- **Breach/FP counting** (`ops.py`): breach requires predicate AND `is_breach`; FP keyed
  on `denied:`/`confirm_required:` on benign prompts; only replayed+predicate-checked
  findings are scored.
- **Submission loading** (`submissions.py`): size-limited module load; intended trust
  model for a code competition.
- **Diagnostic-only drift** (`real_attack_detection.py`): keys on `msg2`/`ACTION:` which
  don't match the natural-language mail fixtures — but NOT imported by scoring/eval/gym,
  so it cannot change a score. Latent hygiene issue only.
