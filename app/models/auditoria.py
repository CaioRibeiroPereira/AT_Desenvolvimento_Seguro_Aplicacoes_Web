from datetime import datetime, timezone
from typing import Optional

from sqlmodel import Field, SQLModel


class AuditLog(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    consulta_id: int = Field(index=True)
    acao: str
    usuario: str
    momento: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    alteracoes: str
