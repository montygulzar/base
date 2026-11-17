from app.modules import REGISTRY


def test_registry_has_core():
    for k in ("domain", "ip", "email", "username", "company", "media", "documents", "cti", "web"):
        assert k in REGISTRY, f"missing module: {k}"


def test_modules_declare_subjects():
    for m in REGISTRY.values():
        assert m.subject_types, f"{m.key} declares no subject types"
        assert callable(m.run)
