"""JWT decoder utility — handy for dissecting tokens found in findings.

Does NOT verify the signature — it's an analyst view, not an auth gate.
"""
from __future__ import annotations
import base64
import json
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from ..auth import current_user

router = APIRouter()


class JwtIn(BaseModel):
    token: str


def _b64(s: str) -> dict:
    pad = "=" * (-len(s) % 4)
    return json.loads(base64.urlsafe_b64decode(s + pad))


@router.post("/decode")
async def decode(data: JwtIn, _=Depends(current_user)):
    parts = (data.token or "").split(".")
    if len(parts) < 2:
        raise HTTPException(400, "not a jwt")
    try:
        header = _b64(parts[0])
        payload = _b64(parts[1])
    except Exception as e:
        raise HTTPException(400, f"decode error: {e}")
    return {"header": header, "payload": payload,
            "signature_present": len(parts) >= 3 and bool(parts[2])}
