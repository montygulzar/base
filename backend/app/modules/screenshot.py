"""Headless browser screenshot + DOM capture via Playwright (pre-installed
in the environment). Falls back to source_unavailable if Playwright is
missing. Screenshots are stored under UPLOAD_DIR/<inv>/screenshots/.
"""
from __future__ import annotations
import os
from pathlib import Path
from ..utils.validators import normalise_domain
from ..utils.ssrf import assert_public, SSRFBlocked
from ..config import get_settings
from .base import Module, Finding, Entity, Relationship, CollectionResult, RunContext, register


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    s = get_settings()
    out = CollectionResult()
    v = (subject or "").strip()
    url = v if "://" in v else "https://" + normalise_domain(v)
    try:
        assert_public(url)
    except SSRFBlocked as e:
        out.findings.append(Finding("screenshot", "ssrf_blocked",
                                    {"url": url, "reason": str(e)}, 0.0))
        return out

    try:
        from playwright.async_api import async_playwright
    except Exception:
        out.findings.append(Finding("screenshot", "source_unavailable",
                                    {"reason": "playwright not installed"}, 0.0))
        return out

    d = Path(s.UPLOAD_DIR) / ctx.investigation_id / "screenshots"
    d.mkdir(parents=True, exist_ok=True)
    safe = "".join(c if c.isalnum() else "_" for c in url)[:100] or "url"
    png_path = d / f"{safe}.png"
    html_path = d / f"{safe}.html"

    # Allow an explicit CHROME path (e.g. in CI containers where playwright
    # can't find its default download). Falls back to the bundled browser.
    import os as _os, glob as _glob
    exe = _os.environ.get("CHROME_PATH") or ""
    if not exe:
        for cand in _glob.glob("/opt/pw-browsers/chromium-*/chrome-linux*/chrome"):
            exe = cand
            break
    launch_kwargs: dict = {"headless": True, "args": ["--no-sandbox"]}
    if exe and _os.path.exists(exe):
        launch_kwargs["executable_path"] = exe
    try:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(**launch_kwargs)
            try:
                ctx_b = await browser.new_context(
                    viewport={"width": 1366, "height": 850},
                    device_scale_factor=1,
                    user_agent="Mozilla/5.0 (base-osint/0.1)",
                )
                page = await ctx_b.new_page()
                r = await page.goto(url, wait_until="networkidle", timeout=20000)
                status = r.status if r else None
                await page.screenshot(path=str(png_path), full_page=True)
                html = await page.content()
                html_path.write_text(html, encoding="utf-8")
                title = await page.title()
            finally:
                await browser.close()
    except Exception as e:
        out.findings.append(Finding("screenshot", "error", {"error": str(e)}, 0.1))
        return out

    out.entities.append(Entity("url", url, {}, 0.9))
    out.findings.append(Finding("playwright", "screenshot", {
        "url": url, "status": status, "title": title,
        "png_path": str(png_path), "html_path": str(html_path),
        "png_bytes": png_path.stat().st_size if png_path.exists() else 0,
    }, 0.95))
    return out


register(Module(
    key="screenshot",
    name="Headless screenshot (Playwright)",
    subject_types=["url", "domain"],
    description="Chromium full-page screenshot + rendered DOM capture.",
    run=run,
))
