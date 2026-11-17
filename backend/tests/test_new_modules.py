from app.modules import REGISTRY


def test_new_modules_present():
    for k in ("passive_dns", "wayback", "crawler", "metagoofil",
              "intelx", "reverse_image", "censys", "urlscan"):
        assert k in REGISTRY, f"missing: {k}"


def test_subject_type_coverage():
    all_subject_types = {t for m in REGISTRY.values() for t in m.subject_types}
    assert {"domain", "ip", "email", "username", "company", "media", "document", "url"} <= all_subject_types
