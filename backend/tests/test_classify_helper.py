"""Expand coverage on the IOC classifier + detect endpoint."""
from app.api.ingest import classify


def test_url_variants():
    assert classify("http://example.com/foo") == ("url", "http://example.com/foo")
    assert classify("https://sub.example.com") == ("url", "https://sub.example.com")


def test_email_lowercases():
    assert classify("MIX@eXaMpLe.COM") == ("email", "mix@example.com")


def test_ipv6():
    assert classify("2001:4860:4860::8888") == ("ip", "2001:4860:4860::8888")


def test_md5_sha1_sha256():
    assert classify("d41d8cd98f00b204e9800998ecf8427e") == ("hash", "d41d8cd98f00b204e9800998ecf8427e")
    assert classify("da39a3ee5e6b4b0d3255bfef95601890afd80709") == ("hash", "da39a3ee5e6b4b0d3255bfef95601890afd80709")
    assert classify("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == \
        ("hash", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")


def test_cve_lowercase_is_upperized():
    assert classify("cve-2021-44228") == ("cve", "CVE-2021-44228")
