"""Phishing lexicon — classic brand-impersonation keyword detector.

Scans a URL or domain for: well-known impersonation targets (paypal /
microsoft / google / amazon / apple / netflix / facebook / twitter /
instagram / linkedin / dropbox / docusign / office / outlook), common
scam keywords (secure / verify / account / update / login / signin /
wallet / crypto / support / recover / reset / unlock / suspended).
"""
from __future__ import annotations
from urllib.parse import urlparse
from ..utils.validators import normalise_domain
from .base import Module, Finding, Entity, CollectionResult, RunContext, register

BRANDS = ["paypal", "microsoft", "google", "amazon", "apple", "netflix",
          "facebook", "twitter", "instagram", "linkedin", "dropbox",
          "docusign", "office365", "outlook", "ebay", "gmail",
          "icloud", "chase", "wellsfargo", "hsbc", "barclays",
          "revolut", "monzo", "bankofamerica", "metamask", "coinbase",
          "binance", "kraken", "trezor", "ledger", "steam", "roblox"]

SCAMMY = ["secure", "verify", "account", "update", "login", "signin",
          "wallet", "support", "recover", "reset", "unlock",
          "suspended", "payment", "invoice", "refund", "confirm",
          "activate", "notice", "alert", "warning", "urgent"]


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    out = CollectionResult()
    v = (subject or "").strip().lower()
    host = normalise_domain(urlparse(v).hostname or v) if "://" in v else normalise_domain(v)
    path = urlparse(v).path.lower() if "://" in v else ""
    brand_hits = [b for b in BRANDS if b in host]
    scammy_hits = [s for s in SCAMMY if s in host or s in path]
    verdict = "ok"
    if brand_hits and not any(host.endswith(b + ".com") for b in brand_hits):
        verdict = "brand_impersonation_candidate"
    if scammy_hits:
        verdict = "suspicious" if verdict == "ok" else verdict
    out.entities.append(Entity("domain", host, {}, 0.8))
    out.findings.append(Finding("phishing_lexicon", "analysis",
                                {"input": v, "host": host, "path": path,
                                 "brands_mentioned": brand_hits,
                                 "scam_keywords": scammy_hits,
                                 "verdict": verdict}, 0.9))
    return out


register(Module(
    key="phishing_lexicon",
    name="Phishing lexicon",
    subject_types=["url", "domain"],
    description="Brand-impersonation + scam-keyword lexicon check.",
    run=run,
))
