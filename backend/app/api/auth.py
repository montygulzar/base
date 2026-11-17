from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from ..auth import verify_password, create_token, current_user, hash_password, require_role
from ..db import get_session
from ..models import User
from ..schemas import Token, UserOut, UserCreate

router = APIRouter()


@router.post("/login", response_model=Token)
async def login(form: OAuth2PasswordRequestForm = Depends(), db: AsyncSession = Depends(get_session)):
    u = (await db.execute(select(User).where(User.email == form.username))).scalar_one_or_none()
    if not u or not verify_password(form.password, u.password_hash):
        raise HTTPException(401, "invalid credentials")
    return Token(access_token=create_token(u.id, u.role))


@router.get("/me", response_model=UserOut)
async def me(u: User = Depends(current_user)):
    return u


@router.post("/users", response_model=UserOut)
async def create_user(data: UserCreate, _: User = Depends(require_role("admin")), db: AsyncSession = Depends(get_session)):
    if (await db.execute(select(User).where(User.email == data.email))).scalar_one_or_none():
        raise HTTPException(409, "email exists")
    u = User(email=data.email, password_hash=hash_password(data.password), role=data.role)
    db.add(u); await db.commit(); await db.refresh(u)
    return u
