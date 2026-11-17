"""Phone number intelligence (PhoneInfoga-equivalent, no shell).

Validates the number via `phonenumbers`, derives country/region/carrier/
timezones, and reports reserved/toll-free characteristics. Optionally
enriches with Numverify (NUMVERIFY_API_KEY).
"""
from __future__ import annotations
import httpx
from ..config import get_settings
from .base import Module, Finding, Entity, CollectionResult, RunContext, register


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    s = get_settings()
    out = CollectionResult()
    v = (subject or "").strip()
    try:
        import phonenumbers
        from phonenumbers import geocoder, carrier, timezone, NumberParseException
    except Exception:
        out.findings.append(Finding("phone", "source_unavailable",
                                    {"reason": "phonenumbers not installed"}, 0.0))
        return out
    try:
        parsed = phonenumbers.parse(v, None)
    except Exception as e:
        out.findings.append(Finding("phone", "invalid_input", {"input": v, "error": str(e)}, 0.1))
        return out
    valid = phonenumbers.is_valid_number(parsed)
    possible = phonenumbers.is_possible_number(parsed)
    nat = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL)
    intl = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
    e164 = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
    out.entities.append(Entity("phone", e164, {"country_code": parsed.country_code}, 0.95))
    out.findings.append(Finding("phonenumbers", "parsed", {
        "e164": e164, "national": nat, "international": intl,
        "country_code": parsed.country_code,
        "country": geocoder.description_for_number(parsed, "en"),
        "carrier": carrier.name_for_number(parsed, "en"),
        "timezones": list(timezone.time_zones_for_number(parsed)),
        "valid": valid, "possible": possible,
        "number_type": str(phonenumbers.number_type(parsed)),
    }, 0.95 if valid else 0.4))

    key = getattr(s, "NUMVERIFY_API_KEY", "") or ""
    if key:
        async with httpx.AsyncClient() as c:
            try:
                r = await c.get("http://apilayer.net/api/validate",
                                params={"access_key": key, "number": e164}, timeout=15)
                if r.status_code == 200:
                    out.findings.append(Finding("numverify", "validate", r.json(), 0.85))
            except Exception as e:
                out.findings.append(Finding("numverify", "error", {"error": str(e)}, 0.1))
    else:
        out.findings.append(Finding("numverify", "source_unavailable", {"reason": "no api key"}, 0.0))
    return out


register(Module(
    key="phone",
    name="Phone number",
    subject_types=["phone"],
    description="phonenumbers validation + Numverify (optional).",
    run=run,
))
