"""
Rogue access-point detection.

Classifies every BSSID observed during a survey as `secured`, `rogue`,
`hidden`, or `unknown`, using an allow-list fused with heuristics that
remain robust under WPA3 / 802.11w and client MAC randomization
(report Chapter 6):

    H1  Allow-list      BSSID (or OUI prefix) not on the managed list.
    H2  Evil twin       A trusted SSID advertised by an unlisted BSSID.
    H3  Security down-   A clone of a trusted SSID advertising *weaker*
        grade            security than the genuine network (e.g. OPEN/WPA2
                         impersonating a WPA3 SSID).
    H4  Hidden node     A non-broadcast SSID inside a managed network.

Each firing appends a human-readable reason; the final label is the most
severe hypothesis that fired.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Sequence

from .models import AccessPoint, Observation


@dataclass
class AllowList:
    """Known-good inventory for the environment under test."""

    bssids: set[str] = field(default_factory=set)
    oui_prefixes: set[str] = field(default_factory=set)      # e.g. "a4:2b:8c"
    ssids: set[str] = field(default_factory=set)             # trusted network names
    # Expected minimum security per trusted SSID, e.g. {"corp": "WPA3"}.
    ssid_security: dict[str, str] = field(default_factory=dict)

    def knows_bssid(self, bssid: str) -> bool:
        b = bssid.lower()
        if b in {x.lower() for x in self.bssids}:
            return True
        return any(b.startswith(p.lower()) for p in self.oui_prefixes)


_SECURITY_RANK = {"OPEN": 0, "WEP": 1, "WPA": 2, "WPA2": 3, "WPA3": 4, "UNKNOWN": 0}


def _rank(sec: str) -> int:
    """Rank a security label, taking the strongest token in composite labels.

    Handles values like "WPA2/WPA3" or "WPA2 WPA3" by scanning every token
    and returning the highest known rank (0 if none are recognised).
    """
    import re
    tokens = re.split(r"[^A-Z0-9]+", sec.upper())
    ranks = [_SECURITY_RANK[t] for t in tokens if t in _SECURITY_RANK]
    return max(ranks) if ranks else 0


class RogueAPDetector:
    def __init__(self, allow: AllowList) -> None:
        self.allow = allow

    def aggregate(self, observations: Sequence[Observation]) -> dict[str, AccessPoint]:
        """Collapse observations into one AccessPoint per BSSID."""
        aps: dict[str, AccessPoint] = {}
        for o in observations:
            ap = aps.get(o.bssid)
            if ap is None:
                ap = AccessPoint(
                    bssid=o.bssid, ssid=o.ssid, channel=o.channel,
                    band=o.band, security=o.security, pmf=o.pmf,
                )
                aps[o.bssid] = ap
            ap.observe(o)
            if _rank(o.security) > _rank(ap.security):
                ap.security = o.security
        return aps

    def classify(self, observations: Sequence[Observation]) -> list[AccessPoint]:
        aps = self.aggregate(observations)

        # Genuine security level expected for each trusted SSID.
        expected = dict(self.allow.ssid_security)
        for ap in aps.values():
            if self.allow.knows_bssid(ap.bssid):
                expected.setdefault(ap.ssid, ap.security)

        results: list[AccessPoint] = []
        for ap in aps.values():
            reasons: list[str] = []
            known = self.allow.knows_bssid(ap.bssid)

            # H4 — hidden SSID
            if ap.ssid in ("", "<hidden>", None):
                ap.classification = "hidden"
                reasons.append("H4: non-broadcast SSID (hidden node)")

            if not known:
                # H1 — not on the allow-list
                reasons.append("H1: BSSID/OUI not on managed allow-list")
                # H2 — evil twin of a trusted SSID
                if ap.ssid in self.allow.ssids:
                    reasons.append(f"H2: unlisted BSSID advertising trusted SSID '{ap.ssid}'")
                # H3 — security downgrade vs. the genuine SSID
                exp = expected.get(ap.ssid)
                if exp and _rank(ap.security) < _rank(exp):
                    reasons.append(
                        f"H3: security downgrade ({ap.security} < expected {exp})"
                    )
                ap.classification = "rogue"
            elif ap.classification != "hidden":
                ap.classification = "secured"
                reasons.append("allow-listed, no anomaly")

            ap.reasons = reasons
            results.append(ap)

        # Most-severe first for easy reporting.
        severity = {"rogue": 0, "hidden": 1, "unknown": 2, "secured": 3}
        results.sort(key=lambda a: (severity.get(a.classification, 9), -a.best_rssi))
        return results

    @staticmethod
    def rogues(aps: Iterable[AccessPoint]) -> list[AccessPoint]:
        return [a for a in aps if a.classification == "rogue"]
