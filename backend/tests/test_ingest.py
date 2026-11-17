from app.api.ingest import classify


def test_classify_variety():
    assert classify("example.com") == ("domain", "example.com")
    assert classify("https://x.com/y") == ("url", "https://x.com/y")
    assert classify("a@b.com") == ("email", "a@b.com")
    assert classify("8.8.8.8") == ("ip", "8.8.8.8")
    assert classify("CVE-2021-44228") == ("cve", "CVE-2021-44228")
    assert classify("a" * 64) == ("hash", "a" * 64)
    assert classify("not-a-thing!") is None
    assert classify("") is None
