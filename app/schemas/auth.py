from typing import Optional

from pydantic import BaseModel

from app.models.user import Role


class Token(BaseModel):
    access_token: str
    token_type: str


class UserRead(BaseModel):
    id: int
    username: str
    role: Role
    profissional_id: Optional[int] = None
