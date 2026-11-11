"""Core data structures shared across the toolkit."""
from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass, field
from typing import Optional


def hash_mac(mac: str, salt: str = "uav-sniffer") -> str:
    """Return a short, stable, non-reversible token for a MAC address.

    MAC addresses are personal data. We never persist the raw address;
    instead we store a salted hash so devices can still be *counted* and
    *correlated within a run* without being re-identified afterwards.
    """
    digest = hashlib.sha256(f"{salt}:{mac.lower()}".encode()).hexdigest()
    return digest[:12]


@dataclass(frozen=True)
class GeoBox:
    """Axis-aligned geographic bounding box for the survey area."""

    lat_min: float
    lon_min: float
    lat_max: float
    lon_max: float

    @property
    def width_m(self) -> float:
        """Approximate east-west width in metres (equirectangular)."""
        mean_lat = math.radians((self.lat_min + self.lat_max) / 2)
        return abs(self.lon_max - self.lon_min) * 111_320 * math.cos(mean_lat)

    @property
    def height_m(self) -> float:
        """Approximate north-south height in metres."""
        return abs(self.lat_max - self.lat_min) * 110_540


@dataclass(frozen=True)
class Obstacle:
    """A polygonal obstacle given as (x, y) metric vertices."""

    vertices: tuple[tuple[float, float], ...]

    def contains(self, x: float, y: float) -> bool:
        """Ray-casting point-in-polygon test (no external deps)."""
        pts = self.vertices
        inside = False
        n = len(pts)
        j = n - 1
        for i in range(n):
            xi, yi = pts[i]
            xj, yj = pts[j]
            if (yi > y) != (yj > y):
                x_cross = (xj - xi) * (y - yi) / (yj - yi + 1e-12) + xi
                if x < x_cross:
                    inside = not inside
            j = i
        return inside


@dataclass
class Observation:
    """A single wireless sample taken at one UAV position."""

    lat: float
    lon: float
    bssid: str            # already hashed when `anonymize=True` upstream
    ssid: str
    channel: int
    rssi: float           # dBm
    snr: Optional[float] = None          # dB, if the radio reports noise
    band: str = "2.4GHz"                 # 2.4GHz | 5GHz | 6GHz
    security: str = "unknown"            # OPEN | WPA2 | WPA3 | ...
    pmf: Optional[bool] = None           # 802.11w protected mgmt frames
    timestamp: float = 0.0

    def is_usable(self, rssi_floor: float = -82.0, snr_floor: float = 10.0) -> bool:
        """Whether this sample represents a usable connection."""
        if self.rssi < rssi_floor:
            return False
        if self.snr is not None and self.snr < snr_floor:
            return False
        return True


@dataclass
class AccessPoint:
    """An aggregated view of one BSSID seen across many observations."""

    bssid: str
    ssid: str
    channel: int
    band: str = "2.4GHz"
    security: str = "unknown"
    pmf: Optional[bool] = None
    best_rssi: float = -120.0
    count: int = 0
    classification: str = "unknown"      # secured | rogue | hidden | unknown
    reasons: list[str] = field(default_factory=list)

    def observe(self, obs: Observation) -> None:
        self.count += 1
        self.best_rssi = max(self.best_rssi, obs.rssi)
