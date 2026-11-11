"""
Dead-zone detection by RF heat-mapping.

Given a set of geo-located Observations, we build a regular grid over the
survey area and interpolate the *best* RSSI available at each grid cell
using an inverse-distance / RBF-style kernel (pure numpy, no SciPy needed).

A cell is:
    dead   if its interpolated best-RSSI < rssi_floor   (unusable)
    weak   if rssi_floor <= RSSI < rssi_warn            (fragile)
    ok     otherwise

Treating coverage as a measured signal surface (rather than a binary
"signal == 0" test) also surfaces *weak* zones before they fail
(report Chapter 5).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

import numpy as np

from .models import GeoBox, Observation


@dataclass
class HeatMap:
    grid_lat: np.ndarray      # (R, C)
    grid_lon: np.ndarray      # (R, C)
    rssi: np.ndarray          # (R, C) interpolated best RSSI in dBm
    status: np.ndarray        # (R, C) int: 0=dead, 1=weak, 2=ok
    coverage: np.ndarray      # (R, C) bool: any observation within support

    DEAD, WEAK, OK = 0, 1, 2

    @property
    def dead_fraction(self) -> float:
        return float(np.mean(self.status == self.DEAD))

    @property
    def weak_fraction(self) -> float:
        return float(np.mean(self.status == self.WEAK))


class DeadZoneMapper:
    def __init__(
        self,
        area: GeoBox,
        resolution: int = 48,
        rssi_floor: float = -82.0,
        rssi_warn: float = -72.0,
        power: float = 2.0,
    ) -> None:
        self.area = area
        self.resolution = int(resolution)
        self.rssi_floor = float(rssi_floor)
        self.rssi_warn = float(rssi_warn)
        self.power = float(power)

    def build(self, observations: Sequence[Observation]) -> HeatMap:
        if not observations:
            raise ValueError("need at least one observation to build a heatmap")

        # Reduce to the strongest RSSI available at each unique sample point:
        # the heatmap models "best achievable signal from any AP", and the UAV
        # usually hears several APs at one GPS fix.
        best: dict[tuple[float, float], float] = {}
        for o in observations:
            key = (round(o.lat, 6), round(o.lon, 6))
            if key not in best or o.rssi > best[key]:
                best[key] = o.rssi
        pts = np.array(list(best.keys()))
        lats, lons = pts[:, 0], pts[:, 1]
        rssis = np.array(list(best.values()))

        r = self.resolution
        gy = np.linspace(self.area.lat_min, self.area.lat_max, r)
        gx = np.linspace(self.area.lon_min, self.area.lon_max, r)
        grid_lon, grid_lat = np.meshgrid(gx, gy)

        # Scale lon/lat to metres so distance is isotropic.
        sx = 111_320.0 * np.cos(np.radians((self.area.lat_min + self.area.lat_max) / 2))
        sy = 110_540.0
        px, py = lons * sx, lats * sy
        qx, qy = grid_lon * sx, grid_lat * sy

        interp = np.empty_like(grid_lat)
        coverage = np.zeros_like(grid_lat, dtype=bool)
        # A cell counts as "surveyed" if a sample lies within the larger of
        # three median sample spacings or ~1.5 grid cells — so a reasonably
        # dense survey never reports spurious no-coverage holes.
        cell_m = max(self.area.width_m, self.area.height_m) / max(r - 1, 1)
        support_m = max(3.0 * _median_spacing(px, py), 1.5 * cell_m)

        for i in range(r):
            for j in range(r):
                d = np.hypot(px - qx[i, j], py - qy[i, j])
                coverage[i, j] = bool(np.any(d <= support_m))
                w = 1.0 / np.power(d + 1e-6, self.power)
                interp[i, j] = float(np.sum(w * rssis) / np.sum(w))

        status = np.full_like(interp, HeatMap.OK, dtype=int)
        status[interp < self.rssi_warn] = HeatMap.WEAK
        status[interp < self.rssi_floor] = HeatMap.DEAD
        # Areas with no nearby samples are treated as dead (unknown == no service).
        status[~coverage] = HeatMap.DEAD

        return HeatMap(grid_lat, grid_lon, interp, status, coverage)

    @staticmethod
    def dead_zone_cells(hm: HeatMap) -> list[tuple[float, float]]:
        """Return (lat, lon) centres of all dead cells."""
        mask = hm.status == HeatMap.DEAD
        return list(zip(hm.grid_lat[mask].tolist(), hm.grid_lon[mask].tolist()))


def _median_spacing(px: np.ndarray, py: np.ndarray) -> float:
    """Median nearest-neighbour spacing of the sample points (metres)."""
    if len(px) < 2:
        return 10.0
    pts = np.column_stack([px, py])
    # O(n^2) is fine for survey-scale point counts.
    d = np.hypot(pts[:, None, 0] - pts[None, :, 0], pts[:, None, 1] - pts[None, :, 1])
    np.fill_diagonal(d, np.inf)
    return float(np.median(np.min(d, axis=1)))
