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
    def __init__(self, config: Optional[Mapping[str, Any]] = None) -> None: ...
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
    def from_messages(cls, user_messages: Sequence[str]) -> "AttackCandidate": ...
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
```

Current behavior:

- guardrail evaluation constructs fresh guardrail instances for replays and benign trials
- cache heavyweight immutable resources outside the instance when possible
- keep per-session mutable state on the instance itself

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

### `evaluation_redteam.py`

Current purpose:

- public Kaggle-style standalone scorer
- expects `attack.py`
- defaults to `--budget-s 1800`
- defaults to `--env gym`
- reports normalized attack score only

Implementation note: this entrypoint lives at [`../evaluation_redteam.py`](../evaluation_redteam.py).

### `evaluation.py`

Current purpose:

- package dual-track evaluator
- expects `--submission_zip submission.zip`
- defaults to `--budget-s 3600`
- splits budget evenly between attack and defense
- defaults to `--env sandbox`

Implementation note: this entrypoint lives at [`../evaluation.py`](../evaluation.py).

## CLI

Installed console entrypoint:

```bash
aicomp
```

Current subcommands:

- `init`
- `validate`
- `test`
- `compare`
- `history`
- `visualize`

### `aicomp test`

Most important current options:

- `--track {auto, redteam, dual, defense}`
- `--budget-s` with default `3600`
- `--agent`
- `--env`
- `--quick`
- `--fixtures_dir`

Current env defaults:

- `redteam` defaults to `gym`
- `defense` and `dual` default to `sandbox`

### Common CLI Examples

```bash
aicomp init attack
aicomp init guardrail
aicomp validate attack.py
aicomp validate guardrail.py --type guardrail
aicomp test attack.py --track redteam --quick
aicomp test attack.py --track redteam --budget-s 1800 --env gym
aicomp test guardrail.py --track defense --quick
aicomp test submission.zip --track dual --quick
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
