from app.modules.typosquat import _variants


def test_variants_basic():
    v = _variants("google")
    assert "googel" in v or "goolge" in v  # swap
    assert any(c.startswith("g") and len(c) == 5 for c in v)  # omission
    # must not include self
    assert "google" not in v
    # bounded size
    assert len(v) < 5000


def test_variants_short_input():
    assert _variants("a") == set()
