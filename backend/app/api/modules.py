from fastapi import APIRouter, Depends
from ..auth import current_user
from ..modules import REGISTRY

router = APIRouter()


@router.get("")
async def list_modules(_: object = Depends(current_user)):
    return [
        {"key": m.key, "name": m.name, "description": m.description, "subject_types": m.subject_types}
        for m in REGISTRY.values()
    ]
