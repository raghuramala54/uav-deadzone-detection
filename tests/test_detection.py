from uav_sniffer.models import GeoBox, Observation
from uav_sniffer.deadzone import DeadZoneMapper, HeatMap
from uav_sniffer.rogue_ap import AllowList, RogueAPDetector
from uav_sniffer import sniffer


AREA = GeoBox(17.470, 78.360, 17.474, 78.365)


def test_synthetic_survey_has_dead_corner():
    obs = sniffer.synthetic(n_samples=800, anonymize=False)
    hm = DeadZoneMapper(AREA).build(obs)
    # The synthetic generator carves a dead corner, so some cells must be dead.
    assert hm.dead_fraction > 0.0
    assert hm.status.shape == (48, 48)


def test_heatmap_status_values_valid():
    obs = sniffer.synthetic(n_samples=400, anonymize=False)
    hm = DeadZoneMapper(AREA).build(obs)
    assert set(hm.status.ravel().tolist()) <= {HeatMap.DEAD, HeatMap.WEAK, HeatMap.OK}


def test_rogue_detection_flags_evil_twin():
    obs = sniffer.synthetic(n_samples=600, include_rogue=True, anonymize=False)
    allow = AllowList(
        oui_prefixes={"a4:2b:8c"},
        ssids={"campus-wifi"},
        ssid_security={"campus-wifi": "WPA2/WPA3"},
    )
    aps = RogueAPDetector(allow).classify(obs)
    rogues = [a for a in aps if a.classification == "rogue"]
    assert any(a.bssid == "de:ad:be:ef:00:01" for a in rogues)
    # The rogue is an OPEN clone of a WPA SSID -> downgrade reason must fire.
    rogue = next(a for a in rogues if a.bssid == "de:ad:be:ef:00:01")
    assert any("H3" in r for r in rogue.reasons)


def test_legit_aps_marked_secured():
    obs = sniffer.synthetic(n_samples=600, include_rogue=False, anonymize=False)
    allow = AllowList(oui_prefixes={"a4:2b:8c"}, ssids={"campus-wifi"})
    aps = RogueAPDetector(allow).classify(obs)
    assert all(a.classification == "secured" for a in aps)


def test_observation_usability_threshold():
    strong = Observation(0, 0, "x", "net", 36, rssi=-60, snr=25)
    weak = Observation(0, 0, "x", "net", 36, rssi=-90, snr=4)
    assert strong.is_usable()
    assert not weak.is_usable()
