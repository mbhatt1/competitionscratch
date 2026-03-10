# API Reference

This reference covers the public SDK surface most relevant to Kaggle red-team submissions.

> Official Kaggle path: `attack.py` only. Guardrail and dual-track APIs remain available for local experimentation.

## Attack Submission Types

### `AttackAlgorithmBase`

Location: `aicomp_sdk.attacks.contracts`

```python
from aicomp_sdk import AttackEnvProtocol


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
    time_budget_s: float
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

`AttackCandidate` is a replay instruction, not a trusted score record. The evaluator replays it and recomputes scoring data.

## Environment Types

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

```python
reset(seed: int | None = None, options: dict[str, Any] | None = None)
step(action: str)
render()
close()
```

Observation shape:
- `turn_index: int`
- `trace_summary_json: str`

Action:
- one user message per `step(action)`

Info payload includes:
- `trace`
- `legacy_result`
- `predicates`
- `cell_signature`
- `breach`
- `max_tool_hops`
- `max_episode_messages`

Compatibility helpers preserved:
- `interact(...)`
- `export_trace_dict()`
- `snapshot()`
- `restore(...)`

### `SandboxEnv`

Location: `aicomp_sdk.core.env`

`SandboxEnv` remains the underlying environment abstraction and is still useful locally.

Evaluator defaults:
- `evaluation_redteam.py` defaults to `GymAttackEnv`
- `evaluation.py` defaults to `SandboxEnv`
- `aicomp test` defaults to `GymAttackEnv` for `--track redteam`
- `aicomp test` defaults to `SandboxEnv` for `--track dual` and `--track defense`

## Predicates

Location: `aicomp_sdk.core.predicates`

Key helper:

```python
from aicomp_sdk.core.predicates import eval_predicates
```

It evaluates a trace dictionary and returns the triggered predicates.

## Scoring Helpers

Location: `aicomp_sdk.scoring`

Useful functions:

```python
score_attack(findings)
score_attack_raw(findings)
score_defense(report)
get_score_breakdown(findings, report)
```

Official Kaggle usage is `score_attack(...)`.

## Evaluators

### `evaluation_redteam.py`

Official Kaggle-style scorer.

```bash
python evaluation_redteam.py \
  --submission attack.py \
  --budget-s 1800 \
  --out scores.txt \
  --out_json results.json \
  --agent deterministic \
  --env gym
```

### `evaluation.py`

Additional zip-based attack+defense evaluator.

```bash
python evaluation.py --submission_zip submission.zip --budget-s 60 --agent deterministic --env sandbox
```

## Selection Options

### Agent selections

| Value | Meaning |
| --- | --- |
| `auto` | Best available backend on the current machine: `gpt_oss`, then `openai`, then `deterministic` |
| `deterministic` | Deterministic vulnerable blue agent for local smoke tests |
| `openai` | Hosted OpenAI-backed blue agent |
| `gpt_oss` | Local GPT-OSS backend; requires local model support |

### Environment selections

| Value | Meaning | Default entrypoints |
| --- | --- | --- |
| `gym` | `GymAttackEnv`, the Gymnasium-compatible wrapper | `evaluation_redteam.py`, `aicomp test --track redteam` |
| `sandbox` | `SandboxEnv`, the direct SDK environment | `evaluation.py`, `aicomp test --track dual`, `aicomp test --track defense` |

## CLI

### Validate

```bash
aicomp validate attack.py
```

### Test

```bash
aicomp test attack.py --track redteam --quick
aicomp test attack.py --track redteam --env sandbox --quick
aicomp test submission.zip --track dual --quick
aicomp test guardrail.py --track defense --quick
```

Track modes:
- `auto`
- `redteam`
- `dual`
- `defense`

## Legacy Guardrail Types

These remain available locally:
- `GuardrailBase`
- `Decision`
- hooks APIs in `aicomp_sdk.guardrails`

They are not required for the official Kaggle submission path.
