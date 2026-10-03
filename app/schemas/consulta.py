from typing import Optional

from pydantic import BaseModel, ConfigDict, Field, NaiveDatetime

from app.models.consulta import StatusConsulta

# whitelist: letras (com acentos), números e pontuação básica de texto médico.
# bloqueia de saída os caracteres usados em XSS (<, >) e em injeção de template/código.
MOTIVO_PATTERN = r"^[A-Za-zÀ-ÿ0-9 .,;:()\-\n]+$"


class ConsultaCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    paciente_id: int
    profissional_id: int
    data_hora: NaiveDatetime
    motivo: str = Field(min_length=3, max_length=280, pattern=MOTIVO_PATTERN)
    status: StatusConsulta = StatusConsulta.agendada


class ConsultaUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    data_hora: Optional[NaiveDatetime] = None
    motivo: Optional[str] = Field(
        default=None, min_length=3, max_length=280, pattern=MOTIVO_PATTERN
    )
    status: Optional[StatusConsulta] = None


# só os campos abaixo saem no JSON; created_by/internal_notes ficam de fora.
class ConsultaRead(BaseModel):
    id: int
    paciente_id: int
    profissional_id: int
    data_hora: NaiveDatetime
    motivo: str
    status: StatusConsulta
