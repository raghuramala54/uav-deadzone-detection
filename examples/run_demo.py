#!/usr/bin/env python3
"""
End-to-end offline demo — no radio hardware required.

Produces, under ./out:
    heatmap.png   RSSI heatmap + dead/weak/ok coverage status
    tour.png      obstacle-aware SOM coverage path
    report.json   machine-readable survey summary

Run:
    python examples/run_demo.py
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from uav_sniffer.models import GeoBox, Obstacle
from uav_sniffer.planner import CoveragePlanner
from uav_sniffer.deadzone import DeadZoneMapper
from uav_sniffer.rogue_ap import AllowList, RogueAPDetector
from uav_sniffer import sniffer

OUT = os.path.join(os.path.dirname(__file__), "..", "out")
AREA = GeoBox(17.470, 78.360, 17.474, 78.365)


def main() -> None:
    os.makedirs(OUT, exist_ok=True)

    # 1) Plan an obstacle-aware coverage tour -----------------------------
    obstacle = Obstacle(((180, 150), (330, 150), (330, 300), (180, 300)))
    planner = CoveragePlanner(AREA, reception_radius_m=20.0, obstacles=[obstacle])
    plan = planner.plan()
    print(f"[plan] {len(plan.nodes)} nodes, tour {plan.length:,.0f} m, "
          f"{plan.iterations} SOM iterations")

    # 2) Simulate the survey & detect dead-zones / rogue APs --------------
    obs = sniffer.synthetic(n_samples=600, anonymize=False)
    hm = DeadZoneMapper(AREA).build(obs)
    print(f"[dead] {hm.dead_fraction*100:.1f}% dead, {hm.weak_fraction*100:.1f}% weak")

    allow = AllowList(oui_prefixes={"a4:2b:8c"}, ssids={"campus-wifi"},
                      ssid_security={"campus-wifi": "WPA2/WPA3"})
    aps = RogueAPDetector(allow).classify(obs)
    for ap in aps:
        print(f"[ap]  {ap.classification:8s} {ap.bssid} {ap.ssid} ({ap.security})")

    # 3) Plots -------------------------------------------------------------
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        from matplotlib.colors import ListedColormap
    except Exception:
        print("matplotlib not installed; skipping plots")
        return

    # Coverage tour around the obstacle
    fig, ax = plt.subplots(figsize=(6, 5))
    xs, ys = plan.nodes[:, 0], plan.nodes[:, 1]
    ax.plot(xs, ys, "-", color="#1B6CA8", lw=1.2, zorder=1)
    ax.scatter(xs, ys, s=10, color="#0B2545", zorder=2)
    ov = obstacle.vertices + (obstacle.vertices[0],)
    ax.fill([p[0] for p in ov], [p[1] for p in ov], color="#B4541A", alpha=0.3)
    ax.set_title("Obstacle-aware SOM coverage tour")
    ax.set_xlabel("x (m)"); ax.set_ylabel("y (m)"); ax.set_aspect("equal")
    fig.tight_layout(); fig.savefig(os.path.join(OUT, "tour.png"), dpi=130)
    print(f"wrote {OUT}/tour.png")

    # Heatmap
    fig, (a1, a2) = plt.subplots(1, 2, figsize=(11, 4.4))
    im = a1.imshow(hm.rssi, origin="lower", cmap="viridis", aspect="auto")
    a1.set_title("Interpolated best RSSI (dBm)"); fig.colorbar(im, ax=a1, shrink=0.8)
    a2.imshow(hm.status, origin="lower", aspect="auto", vmin=0, vmax=2,
              cmap=ListedColormap(["#B4231F", "#E0A200", "#1B7F5A"]))
    a2.set_title("Coverage status (dead / weak / ok)")
    fig.tight_layout(); fig.savefig(os.path.join(OUT, "heatmap.png"), dpi=130)
    print(f"wrote {OUT}/heatmap.png")


if __name__ == "__main__":
    main()
