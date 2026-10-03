from datetime import date, datetime, time
from typing import List

from fastapi import APIRouter, Depends, Query
from sqlmodel import Session, select

from app.auth.deps import require_scope
from app.database import get_session
from app.models.consulta import Consulta
from app.schemas.slot import SlotRead

router = APIRouter(prefix="/slots", tags=["slots"])


@router.get(
    "",
    response_model=List[SlotRead],
    dependencies=[Depends(require_scope("slots:read"))],
)
def listar_horarios_ocupados(
    data: date = Query(default_factory=date.today),
    session: Session = Depends(get_session),
) -> List[Consulta]:
    # so profissional_id e data_hora saem daqui: nada de paciente ou motivo
    inicio = datetime.combine(data, time.min)
    fim = datetime.combine(data, time.max)
    query = select(Consulta).where(Consulta.data_hora >= inicio, Consulta.data_hora <= fim)
    return session.exec(query).all()
