# API Reference

Use this page when you need exact SDK contracts, evaluator defaults, or CLI syntax.

This reference documents the current public package surface for `aicomp-sdk`. For workflow selection and tutorials, start with [`README.md`](README.md), [`GETTING_STARTED.md`](GETTING_STARTED.md), [`ATTACKS_GUIDE.md`](ATTACKS_GUIDE.md), or [`GUARDRAILS_GUIDE.md`](GUARDRAILS_GUIDE.md).

## Common Imports

Most users start from the top-level package:

```python
from aicomp_sdk import (
    AttackAlgorithmBase,
    AttackCandidate,
    AttackRunConfig,
    Decision,
    GuardrailBase,
    GymAttackEnv,
    SandboxEnv,
)
```

The package also exports hook helpers for power users, but the stable submission contracts are still `AttackAlgorithm.run(...)` and `Guardrail.decide(...)`.

## Attack Contract

### `AttackAlgorithmBase`

Stable contract:

```python
class AttackAlgorithmBase(ABC):
    def __init__(self, config: Mapping[str, Any] | None = None) -> None: ...
    def run(self, env: AttackEnvProtocol, config: AttackRunConfig) -> list[AttackCandidate]: ...
```

Requirements:

- subclass it
- implement `run(...)`
- return `list[AttackCandidate]`

### `AttackRunConfig`

Stable contract:

```python
@dataclass(frozen=True)
class AttackRunConfig:
    time_budget_s: float = 30.0
    max_steps: int = 10**9
    max_tool_hops: int = 8
```

Current behavior:

- `time_budget_s` is the wall-clock budget for the run
- `max_steps` is an outer-loop search cap
- `max_tool_hops` is the per-message blue-agent/tool limit used during interaction and replay

### `AttackCandidate`

Stable contract:

```python
@dataclass(frozen=True)
class AttackCandidate:
    user_messages: tuple[str, ...]

    @classmethod
    def from_messages(cls, user_messages: Sequence[str]) -> Self: ...
```

Current replay validation limits:

- at least one message
- non-empty strings only
- at most `32` messages per finding
- at most `2000` characters per message
- at most `2000` replayed findings per run

## Guardrail Contract

### `GuardrailBase`

Stable contract:

```python
class GuardrailBase:
    def decide(
        self,
        tool_name: str,
        tool_args: Mapping[str, Any],
        context: Mapping[str, Any],
    ) -> Decision: ...
    def snapshot_state(self) -> Any: ...
    def restore_state(self, snapshot: Any) -> None: ...
```

Current behavior:

- guardrail evaluation constructs fresh guardrail instances for replays and benign trials
- cache heavyweight immutable resources outside the instance when possible
- keep per-session mutable state on the instance itself
- implement `snapshot_state(...)` / `restore_state(...)` for stateful guardrails that
  need to work correctly with snapshot-based attackers

Current context keys passed by `SandboxEnv`:

- `seed`
- `recent_sources`
- `recent_tools`
- `last_user`
- `side_effect`
- `scope`

### `Decision`

Stable contract:

```python
Decision.allow(reason: str = "")
Decision.deny(reason: str = "")
Decision.confirm(reason: str = "")
Decision.sanitize(sanitized_args: Mapping[str, Any], reason: str = "")
```

Current semantics:

- `DENY` records a failed tool attempt and stops the current interaction
- `CONFIRM` is treated as a blocked tool call in evaluator flows
- `SANITIZE` replaces tool arguments before execution

### Hook Helpers for Power Users

Top-level package exports currently include:

- simple hook helpers: `attack_hook`, `defense_hook`, `clear_hooks`, `store_payload`, `poison_tool`
- advanced hook types and factories: `HookRegistry`, `HookStage`, `HookContext`, `HookResult`, `get_hook_registry`, and the `create_*` helpers

Use these only when the basic `Guardrail.decide(...)` contract is not enough for your workflow.

## Environments

### `SandboxEnv`

Stable constructor:

```python
SandboxEnv(
    seed: int,
    fixtures_dir: Path,
    agent: AgentProtocol,
    guardrail: GuardrailBase | None = None,
    hook_registry: HookRegistry | None = None,
)
```

Current methods:

- `reset() -> None`
- `interact(user_message, max_tool_hops=8) -> EnvInteractionResult`
- `export_trace_dict() -> dict[str, Any]`
- `snapshot()`
- `restore(snapshot)`

Current behavior:

- direct `SandboxEnv(...)` construction requires an explicit `agent=` instance as of `2.0.0`
- `fixtures_dir` must point at a valid fixtures root
- package evaluators can resolve packaged fixtures automatically

Evaluator attack phases expose an opaque `AttackEnvProtocol` wrapper by default. Direct
`SandboxEnv(...)` and `GymAttackEnv(...)` construction still expose harness internals for
debugging and guardrail development.

### `GymAttackEnv`

Stable constructor:

```python
GymAttackEnv(
    seed: int,
    fixtures_dir: Path,
    guardrail: GuardrailBase,
    agent: AgentProtocol,
    max_tool_hops: int = 8,
    max_episode_messages: int = 32,
    reward_mode: Literal["none"] = "none",
)
```

Gym methods:

- `reset(seed=None, options=None)`
- `step(action)`
- `render()`
- `close()`

Current `step(...)` behavior:

- reward is always `0.0`
- `terminated` is always `False`
- `truncated` is driven by `max_episode_messages`

Observation keys:

- `turn_index`
- `trace_summary_json`

Info keys:

- `trace`
- `interaction_result`
- `predicates`
- `cell_signature`
- `breach`
- `max_tool_hops`
- `max_episode_messages`

## Agents and Tool Surface

Current agent selections:

| Value | Meaning |
| --- | --- |
| `auto` | prefer `gpt_oss`, then `openai` if `OPENAI_API_KEY` is set, else `deterministic` |
| `deterministic` | local vulnerable baseline agent |
| `openai` | OpenAI Responses-backed agent |
| `gpt_oss` | local GPT-OSS backend |
| `gemma` | local Gemma backend |

Current canonical tools:

- `web.search`
- `web.open`
- `fs.read`
- `fs.write`
- `fs.delete`
- `shell.run`
- `email.list`
- `email.read`
- `email.send`
- `http.post`

## Evaluators

Command choice:

- Use `aicomp evaluate` for scorer-style runs and stable machine-readable artifacts.
- Use `aicomp test` for local iteration with saved history plus `compare` / `visualize`.

### `aicomp evaluate`

Current purpose:

- standalone evaluator for redteam, defense, and dual-track workflows
- expects the `redteam`, `defense`, or `dual` subcommand
- expects a positional submission path: a Python file for `redteam`/`defense`, or `submission.zip` for `dual`
- defaults to `--budget-s 1800` for redteam and defense, `3600` total for dual
- defaults to `--env sandbox`
- defaults to `--artifacts-dir evaluation_artifacts`
- defaults to `--verbosity summary`
- supports `--verbosity {summary, progress, debug}`
- writes `score.txt` and `report.json` under the artifact directory
- supports `--save-transcript` for `transcript.log`
- supports `--save-framework-events` for `framework.jsonl`
- supports `--save-agent-debug` for `agent-debug.jsonl`

Attack evaluator entrypoints resolve their target guardrail from `AICOMP_ATTACK_GUARDRAIL_ID`
and fall back to `optimal_public`. `AttackEvalOptions` is the programmatic options type for
attack evaluation; `RedteamRunOptions` remains as a compatibility alias.

### Custom Attack Guardrails

Attack evaluator entrypoints support custom guardrails for `evaluate redteam`, `test redteam`,
and the offense phase of `dual`.

For CLI and container runs, install a package that exposes an entry point in the
`aicomp_sdk.attack_guardrails` group:

```toml
[project.entry-points."aicomp_sdk.attack_guardrails"]
private_v1 = "your_private_pkg.guardrail:PrivateGuardrail"
```

Then select it at runtime with:

```bash
AICOMP_ATTACK_GUARDRAIL_ID=private_v1 aicomp evaluate redteam attack.py
```

For in-process tests and embedding, register a spec programmatically:

```python
from aicomp_sdk.evaluation import AttackGuardrailSpec, register_attack_guardrail_spec

register_attack_guardrail_spec(
    AttackGuardrailSpec(
        id="private_v1",
        version="1",
        guardrail_factory=PrivateGuardrail,
    )
)
```

Resolution behavior:

- explicit `AttackEvalOptions.guardrail_factory` wins for programmatic `eval_attack(...)`
- otherwise `AICOMP_ATTACK_GUARDRAIL_ID` selects the guardrail id
- otherwise the evaluator falls back to `optimal_public`
- duplicate ids across built-ins, registered specs, and entry points fail closed

## CLI

Installed console entrypoint:

```bash
aicomp
```

Current subcommands:

- `init`
- `validate`
- `evaluate`
- `test`
- `compare`
- `history`
- `visualize`

### `aicomp test`

Most important current options:

- explicit track subcommands: `redteam`, `defense`, `dual`
- `--budget-s` with default `3600`
  This becomes `3600` attack seconds for `redteam`, `3600` defense seconds for `defense`, and `1800`/`1800` for `dual`.
- `--agent`
- `--verbosity {summary, progress, debug}`
- `--transcript-file PATH`
- `--event-log-file PATH`
- `--agent-debug-jsonl PATH`
- `--env`
- `--fixtures-dir`

Current env defaults:

- `redteam`, `defense`, and `dual` all default to `sandbox`
- pass `--env gym` explicitly when you want GymAttackEnv

### Common CLI Examples

```bash
aicomp init attack
aicomp init guardrail
aicomp validate redteam attack.py
aicomp validate defense guardrail.py
aicomp evaluate redteam attack.py --budget-s 60
aicomp test redteam attack.py --budget-s 1800 --env gym
aicomp test defense guardrail.py --budget-s 60
aicomp test dual submission.zip --budget-s 60
```

## Scoring Helpers

Module-level utilities in `aicomp_sdk.scoring`:

```python
from aicomp_sdk.scoring import (
    get_score_breakdown,
    score_attack,
    score_attack_raw,
    score_defense,
)
```

Use these when you need programmatic scoring helpers outside the main evaluator entrypoints.

## References

- [`SCORING.md`](SCORING.md)
- [`GETTING_STARTED.md`](GETTING_STARTED.md)
- [`ATTACKS_GUIDE.md`](ATTACKS_GUIDE.md)
- [`GUARDRAILS_GUIDE.md`](GUARDRAILS_GUIDE.md)
