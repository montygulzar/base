import pytest
from app.utils.ssrf import assert_public, SSRFBlocked


def test_blocks_localhost():
    with pytest.raises(SSRFBlocked):
        assert_public("http://127.0.0.1/")


def test_blocks_private_range():
    with pytest.raises(SSRFBlocked):
        assert_public("http://10.0.0.1/")


def test_blocks_link_local():
    with pytest.raises(SSRFBlocked):
        assert_public("http://169.254.169.254/latest/meta-data/")


def test_blocks_bad_scheme():
    with pytest.raises(SSRFBlocked):
        assert_public("file:///etc/passwd")


def test_allows_public():
    assert_public("https://example.com/") == "https://example.com/"
