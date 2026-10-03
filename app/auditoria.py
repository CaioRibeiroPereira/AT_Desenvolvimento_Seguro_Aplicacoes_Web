import json
from typing import Optional

from sqlmodel import Session

from app.models.auditoria import AuditLog
from app.models.consulta import Consulta
from app.models.user import User

CAMPOS_AUDITADOS = ("paciente_id", "profissional_id", "data_hora", "motivo", "status")


def snapshot(consulta: Consulta) -> dict:
    return {campo: getattr(consulta, campo) for campo in CAMPOS_AUDITADOS}


def registrar(
    session: Session,
    user: User,
    acao: str,
    consulta_id: int,
    antes: Optional[dict],
    depois: Optional[dict],
) -> None:
    antes, depois = antes or {}, depois or {}
    alteracoes = {
        campo: {"antes": antes.get(campo), "depois": depois.get(campo)}
        for campo in CAMPOS_AUDITADOS
        if antes.get(campo) != depois.get(campo)
    }
    session.add(
        AuditLog(
            consulta_id=consulta_id,
            acao=acao,
            usuario=user.username,
            alteracoes=json.dumps(alteracoes, default=str, ensure_ascii=False),
        )
    )
