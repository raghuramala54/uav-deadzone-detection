"""
Command-line interface for the UAV dead-zone / rogue-AP toolkit.

Examples
--------
    # Plan a coverage tour over a bounding box with one obstacle
    uav-sniffer plan --box 17.470 78.360 17.474 78.365 --radius 15

    # Run the full offline demo on synthetic data and write a heatmap PNG
    uav-sniffer demo --out out/

    # Analyse a real capture (requires scapy)
    uav-sniffer analyse --pcap survey.pcap --box 17.470 78.360 17.474 78.365
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Sequence

from .models import GeoBox, Obstacle
from .planner import CoveragePlanner
from .deadzone import DeadZoneMapper, HeatMap
from .rogue_ap import AllowList, RogueAPDetector
from . import sniffer


def _add_box(p: argparse.ArgumentParser) -> None:
    p.add_argument("--box", nargs=4, type=float, metavar=("LATMIN", "LONMIN", "LATMAX", "LONMAX"),
                   required=True, help="survey bounding box")
    p.add_argument("--radius", type=float, default=15.0, help="reception radius in metres")


def _obstacles_from_arg(spec: str | None) -> list[Obstacle]:
    """Parse '--obstacle x1,y1;x2,y2;...' (metres). Repeatable via JSON file."""
    if not spec:
        return []
    if os.path.isfile(spec):
        data = json.load(open(spec))
        return [Obstacle(tuple(map(tuple, poly))) for poly in data]
    verts = [tuple(map(float, pair.split(","))) for pair in spec.split(";")]
    return [Obstacle(tuple(verts))]


def cmd_plan(args) -> int:
    area = GeoBox(*args.box)
    obstacles = _obstacles_from_arg(args.obstacle)
    planner = CoveragePlanner(area, args.radius, obstacles)
    res = planner.plan(use_som=not args.no_som)
    print(f"nodes planned : {len(res.nodes)}")
    print(f"tour length   : {res.length:,.1f} m")
    print(f"SOM iterations: {res.iterations}")
    if args.out:
        os.makedirs(args.out, exist_ok=True)
        path = os.path.join(args.out, "tour.csv")
        with open(path, "w") as fh:
            fh.write("order,x_m,y_m\n")
            for i, (x, y) in enumerate(res.nodes):
                fh.write(f"{i},{x:.2f},{y:.2f}\n")
        print(f"wrote {path}")
    return 0


def _summarise(observations, area: GeoBox, allow: AllowList, out: str | None) -> int:
    mapper = DeadZoneMapper(area)
    hm = mapper.build(observations)
    print(f"observations  : {len(observations)}")
    print(f"dead cells    : {hm.dead_fraction*100:5.1f}%")
    print(f"weak cells    : {hm.weak_fraction*100:5.1f}%")

    detector = RogueAPDetector(allow)
    aps = detector.classify(observations)
    print("\naccess points:")
    for ap in aps:
        flag = {"rogue": "⚠ ROGUE", "hidden": "· hidden",
                "secured": "✓ secured"}.get(ap.classification, ap.classification)
        print(f"  {flag:10s} {ap.bssid}  ssid={ap.ssid!r:16s} "
              f"ch={ap.channel:<3} sec={ap.security:9s} rssi={ap.best_rssi:6.1f} "
              f"seen={ap.count}")
        for r in ap.reasons:
            print(f"             ↳ {r}")

    if out:
        os.makedirs(out, exist_ok=True)
        _try_plot(hm, os.path.join(out, "heatmap.png"))
        report = {
            "observations": len(observations),
            "dead_fraction": hm.dead_fraction,
            "weak_fraction": hm.weak_fraction,
            "access_points": [
                {"bssid": a.bssid, "ssid": a.ssid, "channel": a.channel,
                 "security": a.security, "best_rssi": a.best_rssi,
                 "classification": a.classification, "reasons": a.reasons}
                for a in aps
            ],
        }
        with open(os.path.join(out, "report.json"), "w") as fh:
            json.dump(report, fh, indent=2)
        print(f"\nwrote {out}/report.json")
    return 0


def cmd_demo(args) -> int:
    area = GeoBox(17.470, 78.360, 17.474, 78.365)
    observations = sniffer.synthetic(n_samples=args.samples, anonymize=False)
    allow = AllowList(
        oui_prefixes={"a4:2b:8c"},          # all four managed APs share this OUI
        ssids={"campus-wifi"},
        ssid_security={"campus-wifi": "WPA2/WPA3"},
    )
    return _summarise(observations, area, allow, args.out)


def cmd_analyse(args) -> int:
    area = GeoBox(*args.box)
    observations = sniffer.from_pcap(args.pcap, anonymize=not args.keep_mac)
    allow = AllowList(bssids=set(args.allow or []))
    return _summarise(observations, area, allow, args.out)


def _try_plot(hm: HeatMap, path: str) -> None:
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        from matplotlib.colors import ListedColormap
    except Exception:
        print("(matplotlib not installed — skipping heatmap PNG)")
        return
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 4.4))
    im = ax1.imshow(hm.rssi, origin="lower", cmap="viridis", aspect="auto")
    ax1.set_title("Interpolated best RSSI (dBm)")
    fig.colorbar(im, ax=ax1, shrink=0.8)
    cmap = ListedColormap(["#B4231F", "#E0A200", "#1B7F5A"])
    ax2.imshow(hm.status, origin="lower", cmap=cmap, vmin=0, vmax=2, aspect="auto")
    ax2.set_title("Coverage status (dead / weak / ok)")
    for ax in (ax1, ax2):
        ax.set_xlabel("lon index"); ax.set_ylabel("lat index")
    fig.tight_layout()
    fig.savefig(path, dpi=130)
    plt.close(fig)
    print(f"wrote {path}")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="uav-sniffer",
                                description="UAV dead-zone & rogue-AP detection toolkit")
    sub = p.add_subparsers(dest="cmd", required=True)

    pp = sub.add_parser("plan", help="plan a coverage tour")
    _add_box(pp)
    pp.add_argument("--obstacle", help="'x1,y1;x2,y2;...' metres, or path to a JSON file")
    pp.add_argument("--no-som", action="store_true", help="use the boustrophedon seed only")
    pp.add_argument("--out", help="output directory")
    pp.set_defaults(func=cmd_plan)

    pd = sub.add_parser("demo", help="run the offline synthetic demo")
    pd.add_argument("--samples", type=int, default=600)
    pd.add_argument("--out", default="out", help="output directory")
    pd.set_defaults(func=cmd_demo)

    pa = sub.add_parser("analyse", help="analyse a PCAP capture")
    _add_box(pa)
    pa.add_argument("--pcap", required=True)
    pa.add_argument("--allow", nargs="*", help="allow-listed BSSIDs")
    pa.add_argument("--keep-mac", action="store_true", help="do NOT hash MACs (use with care)")
    pa.add_argument("--out", help="output directory")
    pa.set_defaults(func=cmd_analyse)
    return p


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
