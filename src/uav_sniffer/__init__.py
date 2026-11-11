"""
uav_sniffer — UAV-based wireless dead-zone & rogue-AP detection toolkit.

An implementation of the project "Deadzone Detection Based on Packet
Sniffing using UAV".

The package is organised into four cooperating components:

    planner   Coverage-path planning over a grid of sensing nodes
              (Self-Organising Map seeded by a boustrophedon sweep),
              with obstacle-aware node culling.
    sniffer   Passive 802.11 capture (live monitor-mode via Scapy, or
              offline from a PCAP) yielding structured Observations.
    deadzone  RSSI/SNR heat-mapping and dead/weak-zone extraction.
    rogue_ap  Rogue access-point detection from an allow-list plus
              WPA3/802.11w-aware heuristics.

Everything here is PASSIVE by design. See SECURITY.md / the README for
the authorised-use policy.
"""

from .models import Observation, AccessPoint, GeoBox, Obstacle
from .planner import CoveragePlanner
from .deadzone import DeadZoneMapper
from .rogue_ap import RogueAPDetector

__version__ = "2.0.0"
__all__ = [
    "Observation",
    "AccessPoint",
    "GeoBox",
    "Obstacle",
    "CoveragePlanner",
    "DeadZoneMapper",
    "RogueAPDetector",
    "__version__",
]
