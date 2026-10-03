from enum import Enum
from typing import Optional

from pydantic import NaiveDatetime
from sqlmodel import Field, SQLModel


class StatusConsulta(str, Enum):
    agendada = "agendada"
    confirmada = "confirmada"
    cancelada = "cancelada"
    realizada = "realizada"


class Consulta(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    paciente_id: int
    profissional_id: int
    data_hora: NaiveDatetime
    motivo: str
    status: StatusConsulta = StatusConsulta.agendada
    created_by: str
    internal_notes: Optional[str] = None
