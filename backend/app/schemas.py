from datetime import datetime
from typing import Any, Literal
from pydantic import BaseModel, EmailStr, Field


SubjectType = Literal["domain", "ip", "email", "username", "company", "media", "document", "url", "phone"]


class UserCreate(BaseModel):
    email: EmailStr
    password: str
    role: str = "analyst"


class UserOut(BaseModel):
    id: str
    email: str
    role: str
    class Config: from_attributes = True


class LoginIn(BaseModel):
    email: EmailStr
    password: str


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class SubjectIn(BaseModel):
    type: SubjectType
    value: str
    note: str = ""


class SubjectOut(SubjectIn):
    id: str
    class Config: from_attributes = True


class InvestigationCreate(BaseModel):
    name: str
    description: str = ""
    subjects: list[SubjectIn] = Field(default_factory=list)


class InvestigationOut(BaseModel):
    id: str
    name: str
    description: str
    status: str
    created_at: datetime
    updated_at: datetime
    class Config: from_attributes = True


class JobOut(BaseModel):
    id: str
    module: str
    status: str
    error: str
    started_at: datetime | None
    finished_at: datetime | None
    result: dict[str, Any]
    class Config: from_attributes = True


class EntityOut(BaseModel):
    id: str
    type: str
    value: str
    attributes: dict[str, Any]
    confidence: float
    class Config: from_attributes = True


class RelOut(BaseModel):
    id: str
    src_id: str
    dst_id: str
    type: str
    source: str
    confidence: float
    evidence: dict[str, Any]
    class Config: from_attributes = True


class FindingOut(BaseModel):
    id: str
    module: str
    source: str
    kind: str
    data: dict[str, Any]
    confidence: float
    collected_at: datetime
    class Config: from_attributes = True


class RunRequest(BaseModel):
    modules: list[str] | None = None  # None => auto-pick by subject type
    subject_ids: list[str] | None = None  # None => all


class IntegrationOut(BaseModel):
    name: str
    configured: bool
    last_ok_at: datetime | None
    last_error: str
    rate_limit_remaining: int | None
    class Config: from_attributes = True
