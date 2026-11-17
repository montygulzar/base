"""Scratchpad — ad-hoc module invocation without persisting to any
investigation. Returns the raw CollectionResult inline.

Useful for "just answer my question" flows: pick a module, pass a
subject value, get the findings back without creating durable state.
"""
from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from ..auth import require_role
from ..modules import REGISTRY
from ..modules.base import RunContext
from ..config import get_settings
from dataclasses import asdict

router = APIRouter()


class RunIn(BaseModel):
    module: str
    subject: str


@router.post("")
async def run(data: RunIn, _=Depends(require_role("admin", "analyst"))):
    mod = REGISTRY.get(data.module)
    if not mod:
        raise HTTPException(404, f"unknown module '{data.module}'")
    ctx = RunContext(investigation_id="__scratchpad__", subject_id="__scratchpad__",
                     settings=get_settings())
    result = await mod.run(data.subject, ctx)
    return {
        "module": data.module,
        "subject": data.subject,
        "findings": [asdict(f) for f in result.findings],
        "entities": [asdict(e) for e in result.entities],
        "relationships": [asdict(r) for r in result.relationships],
    }
