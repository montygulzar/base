from app.utils.validators import is_email, is_domain, is_ip, is_private_ip, is_username, normalise_domain


def test_email():
    assert is_email("a@b.co")
    assert not is_email("no-at")
    assert not is_email("a@b")


def test_domain():
    assert is_domain("example.com")
    assert is_domain("sub.example.co.uk")
    assert not is_domain("notadomain")


def test_normalise():
    assert normalise_domain("HTTPS://Example.COM/path") == "example.com"


def test_ip():
    assert is_ip("8.8.8.8")
    assert is_ip("2001:4860:4860::8888")
    assert not is_ip("8.8.8.888")
    assert is_private_ip("10.1.2.3")
    assert not is_private_ip("8.8.8.8")


def test_username():
    assert is_username("rac0")
    assert is_username("mon.ty-gulzar_1")
    assert not is_username("$$$")
