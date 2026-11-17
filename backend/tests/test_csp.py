from app.modules.csp import parse_csp, WEAKNESSES


def test_parse_basic():
    p = parse_csp("default-src 'self'; script-src 'self' https://cdn.example.com; object-src 'none'")
    assert p["default-src"] == ["'self'"]
    assert "https://cdn.example.com" in p["script-src"]


def test_weakness_unsafe_inline():
    p = parse_csp("script-src 'self' 'unsafe-inline'")
    assert WEAKNESSES["unsafe_inline_script"](p)


def test_weakness_wildcard():
    p = parse_csp("script-src *")
    assert WEAKNESSES["wildcard_script"](p)


def test_missing_object_src():
    p = parse_csp("default-src 'self'")
    assert WEAKNESSES["missing_object_src"](p)
    assert WEAKNESSES["missing_frame_ancestors"](p)
