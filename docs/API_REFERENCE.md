# API Reference

This reference covers the current public SDK surface and the CLI entrypoints most relevant to users of the repository.

> Official Kaggle path: `attack.py` only. Guardrail and dual-track APIs remain available for local experimentation.

## Attack Types

### `AttackAlgorithmBase`

Location: `aicomp_sdk.attacks.contracts`

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

```python
@dataclass(frozen=True)
class AttackRunConfig:
    time_budget_s: float = 30.0
    max_steps: int = 10**9
    max_tool_hops: int = 8
```

### `AttackCandidate`

```python
@dataclass(frozen=True)
class AttackCandidate:
    user_messages: tuple[str, ...]

    @classmethod
    def from_messages(cls, user_messages: Sequence[str]) -> "AttackCandidate": ...
```

Replay validation currently enforces:

- at least one message
- non-empty strings only
- at most `32` messages per finding
- at most `2000` characters per message
- at most `2000` replayed findings per run

## Environment Types

### `SandboxEnv`

Location: `aicomp_sdk.core.env`

```python
SandboxEnv(
    seed: int,
    fixtures_dir: Path,
    agent: AgentProtocol,
    guardrail: GuardrailBase | None = None,
    hook_registry: HookRegistry | None = None,
)
```

Since `2.0.0`, direct `SandboxEnv(...)` construction requires an explicit `agent=` instance. There is no implicit agent fallback or `agent_mode` argument.

Current methods:

- `reset() -> None`
- `interact(user_message, max_tool_hops=8) -> EnvInteractionResult`
- `export_trace_dict() -> dict[str, Any]`
- `snapshot()`
- `restore(snapshot)`

### `GymAttackEnv`

Location: `aicomp_sdk.core.gym_env`

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

Current `step(...)` semantics:

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

## Guardrails

### `GuardrailBase`

Location: `aicomp_sdk.guardrails.base`

```python
class GuardrailBase:
    def decide(
        self,
        tool_name: str,
        tool_args: Mapping[str, Any],
        context: Mapping[str, Any],
    ) -> Decision: ...
```

Local defense evaluation constructs fresh guardrail instances for replays and benign trials. Cache heavyweight immutable resources outside the instance and keep per-session mutable state on the instance itself.

Current context keys passed by `SandboxEnv`:

- `seed`
- `recent_sources`
- `recent_tools`
- `last_user`
- `side_effect`
- `scope`

### `Decision`

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

## Tool Surface

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

Canonical runtime metadata lives in `aicomp_sdk.core.tools.RuntimeToolSpec`.

## Agents

Current agent selections:

| Value | Meaning |
| --- | --- |
| `auto` | prefer `gpt_oss`, then `openai` if `OPENAI_API_KEY` is set, else `deterministic` |
| `deterministic` | local vulnerable baseline agent |
| `openai` | OpenAI Responses-backed agent |
| `gpt_oss` | local GPT-OSS backend |
| `gemma` | local Gemma backend |

## Evaluators

### `evaluation_redteam.py`

Current purpose:

- official Kaggle-style standalone scorer
- expects `attack.py`
- defaults to `--budget-s 1800`
- defaults to `--env gym`

### `evaluation.py`

Current purpose:

- local dual-track evaluator
- expects `--submission_zip submission.zip`
- defaults to `--budget-s 3600`
- splits budget evenly between attack and defense
- defaults to `--env sandbox`

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

### Common CLI Examples

```bash
aicomp init attack
aicomp validate attack.py
aicomp test attack.py --track redteam --quick
aicomp test attack.py --track redteam --budget-s 1800 --env gym
aicomp test guardrail.py --track defense --quick
aicomp test submission.zip --track dual --quick
```

## Scoring Helpers

Location: `aicomp_sdk.scoring`

Useful functions:

```python
score_attack(findings)
score_attack_raw(findings)
score_defense(report)
get_score_breakdown(findings, report)
```
