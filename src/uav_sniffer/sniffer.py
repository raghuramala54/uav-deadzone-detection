"""
Passive 802.11 capture.

Three sources, same output (an iterable of Observation):

    from_pcap(path)       parse beacon/probe frames from a capture file
    live(iface, ...)      sniff a monitor-mode interface in real time
    synthetic(...)        generate a realistic survey for demos/tests

Scapy is an *optional* dependency: it is imported lazily so the planner,
dead-zone and rogue-AP modules work (and the test suite runs) on machines
without Scapy or a wireless card.  Live capture additionally needs a
monitor-mode interface and root — see the README.

IMPORTANT: capture only on networks you own or are authorised to test.
This module is passive: it reads management frames (beacons/probes) and
never associates, injects, deauthenticates, or decodes payloads.
"""
from __future__ import annotations

import time
from typing import Callable, Iterator, Optional

import numpy as np

from .models import Observation, hash_mac


def _require_scapy():
    try:
        from scapy.all import Dot11, Dot11Beacon, Dot11Elt, RadioTap, rdpcap, sniff  # noqa
    except Exception as exc:  # pragma: no cover - depends on host
        raise RuntimeError(
            "Scapy is required for live/pcap capture. Install with "
            "`pip install scapy` and run with monitor-mode privileges."
        ) from exc
    from scapy import all as scapy_all
    return scapy_all


# --------------------------------------------------------------- parsing
def _security_from_beacon(pkt) -> str:
    """Best-effort security label from beacon capability/RSN/WPA elements."""
    try:
        from scapy.all import Dot11Elt
    except Exception:
        return "unknown"
    has_rsn = pkt.haslayer(Dot11Elt) and _has_elt(pkt, 48)   # RSN -> WPA2/WPA3
    has_wpa = _has_vendor_wpa(pkt)
    cap = int(getattr(pkt, "cap", 0) or 0)
    privacy = bool(cap & 0x10)
    if has_rsn:
        # Distinguishing WPA2 vs WPA3 reliably needs AKM parsing; label coarsely.
        return "WPA2/WPA3"
    if has_wpa:
        return "WPA"
    return "WEP" if privacy else "OPEN"


def _has_elt(pkt, elt_id: int) -> bool:
    from scapy.all import Dot11Elt
    elt = pkt.getlayer(Dot11Elt)
    while elt is not None:
        if int(elt.ID) == elt_id:
            return True
        elt = elt.payload.getlayer(Dot11Elt)
    return False


def _has_vendor_wpa(pkt) -> bool:
    from scapy.all import Dot11Elt
    elt = pkt.getlayer(Dot11Elt)
    while elt is not None:
        if int(elt.ID) == 221 and bytes(elt.info).startswith(b"\x00P\xf2\x01"):
            return True
        elt = elt.payload.getlayer(Dot11Elt)
    return False


def _channel_to_band(channel: int) -> str:
    if 1 <= channel <= 14:
        return "2.4GHz"
    if 32 <= channel <= 177:
        return "5GHz"
    return "6GHz"


def _packet_to_observation(pkt, position: Callable[[], tuple[float, float]],
                           anonymize: bool = True) -> Optional[Observation]:
    from scapy.all import Dot11, Dot11Beacon, Dot11Elt
    if not pkt.haslayer(Dot11Beacon):
        return None
    dot11 = pkt.getlayer(Dot11)
    bssid = (dot11.addr3 or "00:00:00:00:00:00")
    ssid = ""
    elt = pkt.getlayer(Dot11Elt)
    if elt is not None and int(elt.ID) == 0:
        ssid = elt.info.decode(errors="ignore") or "<hidden>"
    channel = 0
    try:
        channel = int(ord(pkt[Dot11Elt:3].info))
    except Exception:
        pass
    rssi = float(getattr(pkt, "dBm_AntSignal", -90) or -90)
    lat, lon = position()
    return Observation(
        lat=lat, lon=lon,
        bssid=hash_mac(bssid) if anonymize else bssid,
        ssid=ssid or "<hidden>",
        channel=channel,
        rssi=rssi,
        band=_channel_to_band(channel),
        security=_security_from_beacon(pkt),
        timestamp=time.time(),
    )


# --------------------------------------------------------------- sources
def from_pcap(path: str, position: Callable[[], tuple[float, float]] | None = None,
              anonymize: bool = True) -> list[Observation]:
    """Parse beacon frames from a PCAP/PCAPNG file into Observations.

    `position` returns the UAV (lat, lon) for each frame; if omitted, all
    frames are tagged (0, 0) — supply a GPS-synced callback for real surveys.
    """
    scapy = _require_scapy()
    pos = position or (lambda: (0.0, 0.0))
    out: list[Observation] = []
    for pkt in scapy.rdpcap(path):
        obs = _packet_to_observation(pkt, pos, anonymize)
        if obs is not None:
            out.append(obs)
    return out


def live(iface: str, position: Callable[[], tuple[float, float]],
         count: int = 0, timeout: Optional[int] = None,
         anonymize: bool = True) -> Iterator[Observation]:
    """Yield Observations from a monitor-mode interface in real time."""
    scapy = _require_scapy()
    buffer: list[Observation] = []

    def _cb(pkt):
        obs = _packet_to_observation(pkt, position, anonymize)
        if obs is not None:
            buffer.append(obs)

    scapy.sniff(iface=iface, prn=_cb, count=count, timeout=timeout, store=False)
    yield from buffer


def synthetic(
    n_samples: int = 600,
    seed: int = 7,
    area: tuple[float, float, float, float] = (17.470, 78.360, 17.474, 78.365),
    include_rogue: bool = True,
    anonymize: bool = True,
) -> list[Observation]:
    """Generate a realistic survey: two legit APs, a dead corner, a rogue twin.

    Useful for demos, documentation screenshots and the test-suite — no radio
    hardware required.
    """
    rng = np.random.default_rng(seed)
    lat0, lon0, lat1, lon1 = area

    dlat, dlon = (lat1 - lat0), (lon1 - lon0)
    # Four legitimate APs on a 2x2 grid so most of the campus is covered.
    legit = [
        dict(bssid="a4:2b:8c:11:22:33", ssid="campus-wifi", channel=36,
             security="WPA2/WPA3", at=(lat0 + 0.28 * dlat, lon0 + 0.28 * dlon)),
        dict(bssid="a4:2b:8c:44:55:66", ssid="campus-wifi", channel=6,
             security="WPA2/WPA3", at=(lat0 + 0.28 * dlat, lon0 + 0.72 * dlon)),
        dict(bssid="a4:2b:8c:77:88:99", ssid="campus-wifi", channel=44,
             security="WPA2/WPA3", at=(lat0 + 0.70 * dlat, lon0 + 0.30 * dlon)),
        dict(bssid="a4:2b:8c:aa:bb:cc", ssid="campus-wifi", channel=11,
             security="WPA2/WPA3", at=(lat0 + 0.68 * dlat, lon0 + 0.70 * dlon)),
    ]
    # Rogue "evil twin": an OPEN clone of campus-wifi near the top-right.
    rogue = dict(bssid="de:ad:be:ef:00:01", ssid="campus-wifi", channel=1,
                 security="OPEN", at=(lat0 + 0.80 * dlat, lon0 + 0.85 * dlon))
    aps = legit + ([rogue] if include_rogue else [])

    sx = 111_320.0 * np.cos(np.radians((lat0 + lat1) / 2))
    sy = 110_540.0
    obs: list[Observation] = []
    for _ in range(n_samples):
        lat = rng.uniform(lat0, lat1)
        lon = rng.uniform(lon0, lon1)
        for ap in aps:
            alat, alon = ap["at"]
            d = np.hypot((lon - alon) * sx, (lat - alat) * sy)  # metres
            # Log-distance path loss + shadowing (indoor/campus-ish model).
            rssi = -30 - 18 * np.log10(max(d, 1.0)) + rng.normal(0, 3)
            # Carve a deliberate dead patch in the top-LEFT (away from the
            # rogue in the top-right) so the heatmap shows a clear hole.
            if lat > lat0 + 0.80 * (lat1 - lat0) and lon < lon0 + 0.22 * (lon1 - lon0):
                rssi -= 32
            if rssi < -95:
                continue
            bssid = ap["bssid"]
            obs.append(Observation(
                lat=lat, lon=lon,
                bssid=hash_mac(bssid) if anonymize else bssid,
                ssid=ap["ssid"], channel=ap["channel"],
                rssi=float(rssi), snr=float(max(0, rssi + 95 + rng.normal(0, 2))),
                band=_channel_to_band(ap["channel"]),
                security=ap["security"], timestamp=time.time(),
            ))
    return obs
