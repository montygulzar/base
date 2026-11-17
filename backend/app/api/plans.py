"""Expose the default orchestration plan per subject type."""
from __future__ import annotations
from fastapi import APIRouter, Depends
from ..auth import current_user
from ..orchestrator import PLAN
from ..modules import REGISTRY

router = APIRouter()


@router.get("")
async def plans(_: object = Depends(current_user)):
    return {t: [{"key": k,
                 "name": REGISTRY[k].name if k in REGISTRY else k,
                 "description": REGISTRY[k].description if k in REGISTRY else ""}
                for k in mods if k in REGISTRY]
            for t, mods in PLAN.items()}
