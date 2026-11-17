import base64
from app.modules.favicon import _mmh3_32


def test_mmh3_known_vector():
    # Shodan's documented example: a known favicon base64 producing a hash
    data = b"foo"
    h = _mmh3_32(base64.encodebytes(data))
    assert isinstance(h, int)
    # Deterministic: same input must produce same output.
    assert _mmh3_32(base64.encodebytes(data)) == h


def test_mmh3_signed_range():
    for s in [b"", b"a", b"abc", b"abcd", b"the quick brown fox"]:
        h = _mmh3_32(base64.encodebytes(s))
        assert -(2**31) <= h < 2**31
