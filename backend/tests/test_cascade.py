"""Cascade engine unit test (proximity math + promotion loop).
Lives on in-memory sqlite, no network hits."""
import asyncio
import pytest
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from app.db import Base
from app import models
from app.cascade import _proximity_bfs, HOP_DECAY


def _make_rel(src, dst, conf):
    r = type("R", (), {})()
    r.src_id, r.dst_id, r.confidence = src, dst, conf
    return r


def test_proximity_bfs_single_hop():
    rels = [_make_rel("a", "b", 0.9)]
    p = _proximity_bfs([], rels, ["a"])
    assert p["a"] == 1.0
    assert abs(p["b"] - (1.0 * HOP_DECAY * 0.9)) < 1e-9


def test_proximity_bfs_multi_hop_decay():
    # a -(0.9)-> b -(0.9)-> c -(0.9)-> d
    rels = [
        _make_rel("a", "b", 0.9),
        _make_rel("b", "c", 0.9),
        _make_rel("c", "d", 0.9),
    ]
    p = _proximity_bfs([], rels, ["a"])
    assert p["a"] == 1.0
    # Each hop multiplies by HOP_DECAY * 0.9
    step = HOP_DECAY * 0.9
    assert abs(p["b"] - step) < 1e-9
    assert abs(p["c"] - step * step) < 1e-9
    assert abs(p["d"] - step * step * step) < 1e-9


def test_proximity_bfs_strongest_path_wins():
    # Two paths from a to d:
    #   a -> b (1.0) -> d (0.5)   weak
    #   a -> c (0.9) -> d (1.0)   strong
    rels = [
        _make_rel("a", "b", 1.0),
        _make_rel("b", "d", 0.5),
        _make_rel("a", "c", 0.9),
        _make_rel("c", "d", 1.0),
    ]
    p = _proximity_bfs([], rels, ["a"])
    strong = 1.0 * HOP_DECAY * 0.9 * HOP_DECAY * 1.0
    weak   = 1.0 * HOP_DECAY * 1.0 * HOP_DECAY * 0.5
    assert abs(p["d"] - max(strong, weak)) < 1e-9


def test_proximity_bfs_disconnected_component():
    # x and y are disconnected from the root a.
    rels = [
        _make_rel("a", "b", 0.9),
        _make_rel("x", "y", 0.9),
    ]
    p = _proximity_bfs([], rels, ["a"])
    assert "a" in p and "b" in p
    assert p.get("x", 0.0) == 0.0
    assert p.get("y", 0.0) == 0.0
