"""Email-format permutation.

Given a subject like 'firstname lastname @ example.com' or just a
domain + a 'name' stored in the subject note, generate common corporate
email formats and MX-verify each one as a reachable domain (no SMTP
delivery testing).
"""
from __future__ import annotations
from ..utils.validators import normalise_domain, is_domain
from .base import Module, Finding, Entity, CollectionResult, RunContext, register


FORMATS = [
    "{f}{l}", "{first}{l}", "{first}.{last}", "{first}_{last}", "{first}-{last}",
    "{first}", "{last}", "{f}.{last}", "{first}.{l}", "{last}{first}",
    "{last}.{first}", "{f}{last}", "{first}{last}", "{last}{f}",
    "{first}{random2}", "{f}{last}{random2}",
]


def _parts(name: str) -> dict:
    tokens = [t for t in name.replace(",", " ").split() if t]
    if not tokens:
        return {}
    first = tokens[0].lower()
    last = tokens[-1].lower() if len(tokens) > 1 else ""
    return {"first": first, "last": last, "f": first[:1], "l": last[:1], "random2": "01"}


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    out = CollectionResult()
    v = (subject or "").strip()
    # Expect either "First Last @ domain.tld" or "domain.tld|First Last"
    name = ""
    domain = ""
    if "@" in v:
        name_part, domain = v.rsplit("@", 1)
        name = name_part.strip()
    elif "|" in v:
        domain, name = [p.strip() for p in v.split("|", 1)]
    else:
        out.findings.append(Finding("email_permute", "invalid_input",
                                    {"expected": "'First Last @ domain' or 'domain|First Last'"}, 0.1))
        return out
    domain = normalise_domain(domain)
    if not is_domain(domain) or not name:
        out.findings.append(Finding("email_permute", "invalid_input", {"name": name, "domain": domain}, 0.1))
        return out
    p = _parts(name)
    if not p:
        out.findings.append(Finding("email_permute", "invalid_input", {"input": v}, 0.1))
        return out

    seen = set()
    emails = []
    for fmt in FORMATS:
        try:
            local = fmt.format(**p)
        except KeyError:
            continue
        local = local.strip(".").strip("_").strip("-").lower()
        if not local or local in seen:
            continue
        seen.add(local)
        emails.append(f"{local}@{domain}")
    out.findings.append(Finding("email_permute", "candidates",
                                {"count": len(emails), "emails": emails}, 0.8))
    for em in emails:
        out.entities.append(Entity("email", em, {"source": "permute",
                                                  "name": name,
                                                  "format": True}, 0.4))
    return out


register(Module(
    key="email_permute",
    name="Email format permutation",
    subject_types=["email", "company"],
    description="Generates common corporate email formats. Candidates only.",
    run=run,
))
