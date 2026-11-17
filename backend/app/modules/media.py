"""Image / media metadata and hashing."""
from __future__ import annotations
import json
import subprocess
from pathlib import Path
from PIL import Image
import imagehash
from ..utils.hashing import sha256_file
from .base import Module, Finding, Entity, CollectionResult, RunContext, register


def _exiftool(path: str) -> dict:
    try:
        r = subprocess.run(["exiftool", "-j", "-n", path], capture_output=True, text=True, timeout=30)
        if r.returncode == 0 and r.stdout.strip():
            arr = json.loads(r.stdout)
            return arr[0] if arr else {}
    except Exception as e:
        return {"error": str(e)}
    return {}


async def run(subject: str, ctx: RunContext) -> CollectionResult:
    """Subject is the absolute path to an uploaded file."""
    out = CollectionResult()
    p = Path(subject)
    if not p.exists() or not p.is_file():
        out.findings.append(Finding("media", "invalid_input", {"path": subject}, 0.1))
        return out

    sha = sha256_file(p)
    out.entities.append(Entity("file", sha, {"name": p.name, "size": p.stat().st_size}, 0.95))
    out.findings.append(Finding("hash", "sha256", {"sha256": sha, "name": p.name, "size": p.stat().st_size}, 1.0))

    exif = _exiftool(str(p))
    out.findings.append(Finding("exiftool", "metadata", exif, 0.9 if exif else 0.2))

    gps = {}
    for k in ("GPSLatitude", "GPSLongitude", "GPSLatitudeRef", "GPSLongitudeRef", "GPSAltitude"):
        if k in exif:
            gps[k] = exif[k]
    if gps:
        out.findings.append(Finding("exiftool", "gps", gps, 0.85))

    try:
        with Image.open(p) as im:
            ph = str(imagehash.phash(im))
            dh = str(imagehash.dhash(im))
            out.findings.append(Finding("imagehash", "perceptual",
                                        {"phash": ph, "dhash": dh, "size": im.size, "mode": im.mode}, 0.9))
            out.entities.append(Entity("hash", ph, {"kind": "phash", "file_sha256": sha}, 0.8))
    except Exception as e:
        out.findings.append(Finding("imagehash", "error", {"error": str(e)}, 0.1))

    return out


register(Module(
    key="media",
    name="Image / media analysis",
    subject_types=["media"],
    description="EXIF, SHA-256, perceptual hash, GPS.",
    run=run,
))
