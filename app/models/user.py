from enum import Enum
from typing import Optional

from sqlmodel import Field, SQLModel


class Role(str, Enum):
    recepcionista = "recepcionista"
    profissional = "profissional"
    admin = "admin"


class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    username: str = Field(index=True, sa_column_kwargs={"unique": True})
    hashed_password: str
    role: Role
    profissional_id: Optional[int] = None
    mfa_secret: Optional[str] = None
