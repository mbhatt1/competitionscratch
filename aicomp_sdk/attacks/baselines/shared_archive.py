"""
Global Shared Archive for Collaborative Multi-Agent Exploration
Enables multiple agents to coordinate exploration without losing strategic diversity
"""

import threading
from typing import Any

from aicomp_sdk.attacks.baselines.attacker_goexplore import Exemplar


class SharedArchive:
    """
    Thread-safe global archive shared across multiple Go-Explore agents.

    Key properties:
    - Agents maintain strategic diversity (different configs)
    - States are shared (consensus on what's been explored)
    - Coordinated selection (avoid redundant exploration)
    """

    def __init__(self):
        self.cells: dict[str, Exemplar] = {}
        self.lock = threading.Lock()
        self.agent_visits: dict[str, dict[str, int]] = {}  # agent_id -> {cell_hash -> visit_count}

    def add_cell(self, cell_hash: str, exemplar: Exemplar, agent_id: str) -> bool:
        """
        Add a new cell to the shared archive.
        Returns True if novel, False if already exists.
        """
        with self.lock:
            if cell_hash not in self.cells:
                self.cells[cell_hash] = exemplar
                return True
            return False

    def select_cell_for_agent(self, agent_id: str, weights_fn=None) -> Exemplar | None:
        """
        Select a cell for an agent to explore.
        Prioritizes cells this agent hasn't visited to avoid redundancy.
        """
        with self.lock:
            if not self.cells:
                return None

            # Initialize agent tracking if needed
            if agent_id not in self.agent_visits:
                self.agent_visits[agent_id] = {}

            # Get cells this agent hasn't heavily explored
            candidates = list(self.cells.values())
            agent_visit_counts = self.agent_visits[agent_id]

            # Compute selection weights
            if weights_fn:
                weights = [
                    weights_fn(ex, agent_visit_counts.get(ex.cell_hash, 0)) for ex in candidates
                ]
            else:
                # Default: prefer cells with low visits from this agent
                max_visits = max(agent_visit_counts.values(), default=1) + 1
                weights = [
                    (max_visits - agent_visit_counts.get(ex.cell_hash, 0)) / max_visits
                    for ex in candidates
                ]

            # Weighted random selection
            import random

            total = sum(weights)
            if total == 0:
                return random.choice(candidates)

            r = random.uniform(0, total)
            cumsum = 0
            for ex, w in zip(candidates, weights):
                cumsum += w
                if r <= cumsum:
                    return ex

            return candidates[-1]

    def record_visit(self, agent_id: str, cell_hash: str):
        """Record that an agent visited/explored from a cell."""
        with self.lock:
            if agent_id not in self.agent_visits:
                self.agent_visits[agent_id] = {}
            self.agent_visits[agent_id][cell_hash] = (
                self.agent_visits[agent_id].get(cell_hash, 0) + 1
            )

    def get_stats(self) -> dict[str, Any]:
        """Get archive statistics."""
        with self.lock:
            return {
                "total_cells": len(self.cells),
                "agent_count": len(self.agent_visits),
                "per_agent_visits": {
                    aid: sum(visits.values()) for aid, visits in self.agent_visits.items()
                },
            }
