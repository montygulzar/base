"""Reverse-image search.

- TinEye MatchEngine (optional key)
- Bing Visual Search (optional key)
- No-key fallback: compute perceptual hash, check Google Images reverse
  URL (returns a browser page, not usable for scrape) — we instead expose
  tineye.com / lens.google.com / images.google.com URLs the analyst can
  click. The hash is still produced as a stable artefact.
"""
from __future__ import annotations
import base64
from pathlib import Path
import httpx
from ..utils.hashing import sha256_file
from ..utils.ratelimit import gate
from ..config import get_settings
from .base import Module, Finding, Entity, Relationship, CollectionResult, RunContext, register


async def _tineye(c: httpx.AsyncClient, image_bytes: bytes, user: str, pw: str) -> dict:
    await gate("tineye")
    try:
        r = await c.post(
            "https://api.tineye.com/rest/search/",
            params={"api_key": pw},
            files={"image_upload": ("image", image_bytes)},
            timeout=30,
        )
        if r.status_code == 200:
            return r.json()
        return {"error": f"status={r.status_code}", "body": r.text[:200]}
    except Exception as e:
        return {"error": str(e)}


async def _bing_visual(c: httpx.AsyncClient, image_bytes: bytes, key: str) -> dict:
    await gate("bing_visual")
    try:
        r = await c.post(
            "https://api.bing.microsoft.com/v7.0/images/visualsearch",
            headers={"Ocp-Apim-Subscription-Key": key},
            files={"image": ("image", image_bytes, "application/octet-stream")},
            timeout=30,
        )
        if r.status_code == 200:
            return r.json()
        return {"error": f"status={r.status_code}", "body": r.text[:200]}
    except Exception as e:
        return {"error": str(e)}


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    s = get_settings()
    out = CollectionResult()
    p = Path(subject)
    if not p.exists() or not p.is_file():
        out.findings.append(Finding("reverse_image", "invalid_input", {"path": subject}, 0.1))
        return out
    sha = sha256_file(p)
    out.entities.append(Entity("file", sha, {"name": p.name, "size": p.stat().st_size}, 0.95))
    out.findings.append(Finding("hash", "sha256",
                                {"sha256": sha, "name": p.name}, 1.0))

    # Deep-link URLs for manual follow-up (no key needed)
    deep = {
        "tineye_upload":  "https://tineye.com/search?url=",
        "google_lens":    "https://lens.google.com/uploadbyurl?url=",
        "yandex_images":  "https://yandex.com/images/search?url=",
        "bing_images":    "https://www.bing.com/images/searchbyimage?cbir=sbi&imgurl=",
    }
    out.findings.append(Finding("reverse_image", "manual_links", deep, 0.8))

    body = p.read_bytes()
    async with httpx.AsyncClient() as c:
        tineye_user = getattr(s, "TINEYE_API_USER", "") or ""
        tineye_pw = getattr(s, "TINEYE_API_KEY", "") or ""
        if tineye_user and tineye_pw:
            res = await _tineye(c, body, tineye_user, tineye_pw)
            out.findings.append(Finding("tineye", "match", res,
                                        0.9 if "error" not in res else 0.1))
        else:
            out.findings.append(Finding("tineye", "source_unavailable", {"reason": "no api key"}, 0.0))

        bing_key = getattr(s, "BING_VISUAL_API_KEY", "") or ""
        if bing_key:
            res = await _bing_visual(c, body, bing_key)
            out.findings.append(Finding("bing_visual", "match", res,
                                        0.9 if "error" not in res else 0.1))
        else:
            out.findings.append(Finding("bing_visual", "source_unavailable", {"reason": "no api key"}, 0.0))

    return out


register(Module(
    key="reverse_image",
    name="Reverse image search",
    subject_types=["media"],
    description="TinEye + Bing Visual (optional keys) + analyst deep-links.",
    run=run,
))
