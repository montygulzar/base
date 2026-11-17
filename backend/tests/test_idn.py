from app.modules.idn_homograph import skeleton, script_mix


def test_skeleton_normalises_cyrillic():
    assert skeleton("pаypal.com") == "paypal.com"  # first 'a' is cyrillic а


def test_skeleton_passes_latin():
    assert skeleton("example.com") == "example.com"


def test_script_mix_detects():
    s = script_mix("pаypal")
    assert "LATIN" in s and "CYRILLIC" in s
