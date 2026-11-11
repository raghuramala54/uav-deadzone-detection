import numpy as np
from uav_sniffer.models import GeoBox, Obstacle
from uav_sniffer.planner import CoveragePlanner


def small_area():
    # ~ 300 m x 300 m box
    return GeoBox(17.4700, 78.3600, 17.4727, 78.3628)


def test_grid_spacing_matches_diameter():
    area = small_area()
    planner = CoveragePlanner(area, reception_radius_m=15.0)
    nodes = planner.generate_nodes()
    assert len(nodes) > 10
    # adjacent column spacing should be ~2*r = 30 m
    xs = np.unique(np.round(nodes[:, 0], 2))
    assert abs((xs[1] - xs[0]) - 30.0) < 1e-6


def test_obstacle_culling_removes_interior_nodes():
    area = small_area()
    obstacle = Obstacle(((100, 100), (200, 100), (200, 200), (100, 200)))
    planner = CoveragePlanner(area, 15.0, [obstacle])
    full = planner.generate_nodes()
    filtered = planner.filter_nodes(full)
    assert len(filtered) < len(full)
    assert not any(obstacle.contains(x, y) for x, y in filtered)


def test_som_tour_shorter_than_random():
    area = small_area()
    planner = CoveragePlanner(area, 15.0, seed=1)
    res = planner.plan(max_iterations=3000)
    nodes = res.nodes
    rng = np.random.default_rng(0)
    random_order = nodes[rng.permutation(len(nodes))]
    assert res.length <= planner.tour_length(random_order)


def test_boustrophedon_only_is_deterministic():
    area = small_area()
    r1 = CoveragePlanner(area, 15.0).plan(use_som=False)
    r2 = CoveragePlanner(area, 15.0).plan(use_som=False)
    assert np.allclose(r1.nodes, r2.nodes)
    assert r1.iterations == 0
