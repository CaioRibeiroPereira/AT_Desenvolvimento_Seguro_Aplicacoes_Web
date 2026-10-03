from typing import Optional

from sqlmodel import Field, SQLModel


class Client(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    client_id: str = Field(index=True, sa_column_kwargs={"unique": True})
    hashed_secret: str
    scopes: str  # espaco-separado, mesmo formato do claim "scope" do JWT
