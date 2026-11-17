import re
import ipaddress
import tldextract

_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
_USER_RE = re.compile(r"^[A-Za-z0-9._\-]{2,64}$")


def is_email(v: str) -> bool:
    return bool(_EMAIL_RE.match(v or ""))


def is_domain(v: str) -> bool:
    if not v or " " in v:
        return False
    ex = tldextract.extract(v)
    return bool(ex.domain and ex.suffix)


def normalise_domain(v: str) -> str:
    v = (v or "").strip().lower()
    v = re.sub(r"^https?://", "", v)
    v = v.split("/", 1)[0].split(":", 1)[0]
    return v


def is_ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


def is_private_ip(v: str) -> bool:
    try:
        return ipaddress.ip_address(v).is_private
    except ValueError:
        return False


def is_username(v: str) -> bool:
    return bool(_USER_RE.match(v or ""))
