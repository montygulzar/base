"""Subject-type autodetect helper.

POST a single value; returns the inferred subject type or null.
"""
from __future__ import annotations
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from ..auth import current_user
from ..api.ingest import classify

router = APIRouter()


class DetectIn(BaseModel):
    value: str


@router.post("")
async def detect(data: DetectIn, _=Depends(current_user)):
    c = classify((data.value or "").strip())
    if not c:
        # try btc / eth / phone minimal regexes
        import re
        v = (data.value or "").strip()
        if re.match(r"^(bc1[a-zA-HJ-NP-Z0-9]{25,87}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})$", v):
            return {"type": "btc", "value": v}
        if re.match(r"^0x[a-fA-F0-9]{40}$", v):
            return {"type": "eth", "value": v}
        if re.match(r"^\+?[0-9\s\-\(\)]{7,}$", v):
            return {"type": "phone", "value": v}
        return {"type": None, "value": v}
    return {"type": c[0], "value": c[1]}
