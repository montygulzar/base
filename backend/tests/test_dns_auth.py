from app.modules.dns_auth import _parse_spf, _parse_dmarc


def test_spf_strict():
    p = _parse_spf("v=spf1 include:_spf.google.com -all")
    assert p["posture"] == "strict_fail"
    assert "include:_spf.google.com" in p["mechanisms"]


def test_spf_soft():
    p = _parse_spf("v=spf1 a mx ~all")
    assert p["posture"] == "soft_fail"


def test_spf_allow_all():
    p = _parse_spf("v=spf1 +all")
    assert p["posture"] == "insecure_allow_all"


def test_dmarc_parse():
    t = _parse_dmarc("v=DMARC1; p=reject; sp=quarantine; rua=mailto:reports@example.com; pct=100")
    assert t["p"] == "reject"
    assert t["sp"] == "quarantine"
    assert t["rua"] == "mailto:reports@example.com"
    assert t["pct"] == "100"
