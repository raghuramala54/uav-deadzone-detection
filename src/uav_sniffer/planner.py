"""
Coverage-path planning over a grid of sensing nodes.

Pipeline (matches the report, Chapter 3):

    1. generate_nodes()  -> uniform grid, spacing = 2 * reception_radius
    2. filter_nodes()    -> drop nodes inside any obstacle polygon
    3. plan()            -> order the surviving nodes into a short tour

The tour is produced by a Self-Organising Map (SOM) *seeded* with a
boustrophedon (ox-like) sweep.  Seeding gives the SOM a near-optimal
starting ring so it converges in a fraction of the iterations a
cold-started network would need, and without hand-tuning the schedule
per map.

Only numpy is required.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Sequence

import numpy as np

from .models import GeoBox, Obstacle


@dataclass
class PlanResult:
    nodes: np.ndarray        # (N, 2) ordered metric coordinates of the tour
    order: np.ndarray        # (N,) indices into the filtered node set
    length: float            # tour length in metres
    iterations: int          # SOM iterations actually run


class CoveragePlanner:
    """Plan an obstacle-aware coverage tour of a rectangular region."""

    def __init__(
        self,
        area: GeoBox,
        reception_radius_m: float = 15.0,
        obstacles: Sequence[Obstacle] | None = None,
        seed: int | None = 42,
    ) -> None:
        self.area = area
        self.reception_radius_m = float(reception_radius_m)
        self.obstacles = list(obstacles or [])
        self.rng = np.random.default_rng(seed)

    # ----------------------------------------------------------------- grid
    def generate_nodes(self) -> np.ndarray:
        """Uniform grid with spacing equal to the reception diameter (2r)."""
        spacing = 2.0 * self.reception_radius_m
        n_cols = max(1, int(self.area.width_m // spacing))
        n_rows = max(1, int(self.area.height_m // spacing))
        xs = (np.arange(n_cols) + 0.5) * spacing
        ys = (np.arange(n_rows) + 0.5) * spacing
        gx, gy = np.meshgrid(xs, ys)
        return np.column_stack([gx.ravel(), gy.ravel()])

    def filter_nodes(self, nodes: np.ndarray) -> np.ndarray:
        """Remove nodes that fall inside any obstacle polygon."""
        if not self.obstacles:
            return nodes
        keep = []
        for x, y in nodes:
            if not any(ob.contains(x, y) for ob in self.obstacles):
                keep.append((x, y))
        return np.asarray(keep, dtype=float) if keep else nodes[:0]

    # ------------------------------------------------------------- planning
    @staticmethod
    def _boustrophedon_order(nodes: np.ndarray) -> np.ndarray:
        """Column-major, back-and-forth ordering of the nodes."""
        xs = np.unique(np.round(nodes[:, 0], 3))
        order: list[int] = []
        for col, x in enumerate(xs):
            idx = np.where(np.isclose(nodes[:, 0], x))[0]
            idx = idx[np.argsort(nodes[idx, 1])]
            if col % 2 == 1:           # reverse every other column -> ox motion
                idx = idx[::-1]
            order.extend(idx.tolist())
        return np.asarray(order, dtype=int)

    @staticmethod
    def tour_length(ordered: np.ndarray, closed: bool = True) -> float:
        if len(ordered) < 2:
            return 0.0
        diffs = np.diff(ordered, axis=0)
        length = float(np.sum(np.hypot(diffs[:, 0], diffs[:, 1])))
        if closed:
            length += float(np.hypot(*(ordered[0] - ordered[-1])))
        return length

    def plan(
        self,
        max_iterations: int = 6000,
        learning_rate: float = 0.8,
        decay: float = 0.9997,
        neurons_per_node: int = 4,
        use_som: bool = True,
    ) -> PlanResult:
        """Return an ordered coverage tour over the filtered nodes."""
        nodes = self.filter_nodes(self.generate_nodes())
        if len(nodes) <= 2:
            order = np.arange(len(nodes))
            return PlanResult(nodes, order, self.tour_length(nodes), 0)

        seed_order = self._boustrophedon_order(nodes)
        if not use_som:
            ordered = nodes[seed_order]
            return PlanResult(ordered, seed_order, self.tour_length(ordered), 0)

        order, iters = self._som(
            nodes, seed_order, max_iterations, learning_rate, decay, neurons_per_node
        )
        ordered = nodes[order]
        return PlanResult(ordered, order, self.tour_length(ordered), iters)

    # ------------------------------------------------------------------ SOM
    def _som(
        self,
        nodes: np.ndarray,
        seed_order: np.ndarray,
        max_iterations: int,
        lr: float,
        decay: float,
        neurons_per_node: int,
    ) -> tuple[np.ndarray, int]:
        """Elastic-ring SOM; neurons initialised along the seed tour."""
        n = len(nodes)
        n_neurons = n * neurons_per_node
        # Initialise the ring by resampling the boustrophedon seed path.
        seed_path = nodes[seed_order]
        t = np.linspace(0, len(seed_path) - 1, n_neurons)
        network = np.array(
            [np.interp(t, np.arange(len(seed_path)), seed_path[:, d]) for d in range(2)]
        ).T

        radius = n_neurons // 4
        it = 0
        for it in range(1, max_iterations + 1):
            city = nodes[self.rng.integers(n)]
            winner = int(np.argmin(np.linalg.norm(network - city, axis=1)))
            # Gaussian neighbourhood around the winner on the ring.
            deltas = np.abs(np.arange(n_neurons) - winner)
            deltas = np.minimum(deltas, n_neurons - deltas)
            gauss = np.exp(-(deltas ** 2) / (2 * (radius + 1e-9) ** 2))
            network += (lr * gauss)[:, None] * (city - network)

            lr *= decay
            radius = max(1, int(radius * 0.9997))
            if lr < 0.001:
                break

        # Map each node to its nearest neuron, then read nodes off in ring order.
        winners = np.array(
            [int(np.argmin(np.linalg.norm(network - nd, axis=1))) for nd in nodes]
        )
        order = np.argsort(winners, kind="stable")
        return order, it


def plan_from_box(
    lat_min: float,
    lon_min: float,
    lat_max: float,
    lon_max: float,
    reception_radius_m: float = 15.0,
    obstacles: Iterable[Obstacle] | None = None,
    **kwargs,
) -> PlanResult:
    """Convenience wrapper used by the CLI and tests."""
    area = GeoBox(lat_min, lon_min, lat_max, lon_max)
    return CoveragePlanner(area, reception_radius_m, list(obstacles or [])).plan(**kwargs)
