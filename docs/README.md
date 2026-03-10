# JED Documentation

This is the documentation hub for the JED SDK and competition tooling.

## Start Here

- [`KAGGLE_REDTEAM_GUIDE.md`](KAGGLE_REDTEAM_GUIDE.md): canonical Kaggle submission guide
- [`GETTING_STARTED.md`](GETTING_STARTED.md): quickest path from install to working `attack.py`
- [`COMPETITION_RULES.md`](COMPETITION_RULES.md): public submission rules and evaluator contract
- [`SCORING.md`](SCORING.md): official attack scoring contract

## Core SDK Docs

- [`ATTACKS_GUIDE.md`](ATTACKS_GUIDE.md): attack-development guidance
- [`API_REFERENCE.md`](API_REFERENCE.md): public SDK interfaces
- [`FAQ.md`](FAQ.md): common questions

## Additional Local Docs

These remain useful for research, local experimentation, and the broader SDK workflow, but they are not the public Kaggle submission contract:

- [`GUARDRAILS_GUIDE.md`](GUARDRAILS_GUIDE.md)
- [`COMPETITION_DESIGN.md`](COMPETITION_DESIGN.md)
- [`TESTING_GUIDE.md`](TESTING_GUIDE.md)

## Examples

- [`../examples/README.md`](../examples/README.md)
- [`../examples/test_attack_submission.py`](../examples/test_attack_submission.py)
- [`../examples/attacks/attack_gym_step.py`](../examples/attacks/attack_gym_step.py)

## Official Kaggle Contract

- submit `attack.py` only
- leaderboard score = normalized attack score only
- default attack budget = `1800` seconds
- Kaggle attack-only scoring defaults to the Gymnasium-compatible env
- local entrypoints can explicitly choose `GymAttackEnv` or `SandboxEnv`

## Local Testing Commands

Official Kaggle-style local scorer:

```bash
python evaluation_redteam.py --submission attack.py --budget-s 60 --agent deterministic --env gym
```

CLI equivalent:

```bash
aicomp test attack.py --track redteam --quick
aicomp test attack.py --track redteam --env sandbox --quick
aicomp test submission.zip --track dual --env gym --quick
```

Additional local helpers:

```bash
aicomp test guardrail.py --track defense --quick
aicomp test submission.zip --track dual --quick
```
