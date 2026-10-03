from datetime import date, datetime, time
from pathlib import Path

import jinja2
from fastapi import APIRouter, Depends, Query, Request
from fastapi.templating import Jinja2Templates
from sqlmodel import Session, select

from app.auth.deps import require_roles
from app.database import get_session
from app.models.consulta import Consulta
from app.models.user import Role

router = APIRouter(tags=["recepcao"])

somente_recepcao_ou_admin = require_roles(Role.recepcionista, Role.admin)

TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"

# autoescape=True explicito: controle central contra XSS stored nesta pagina.
_env = jinja2.Environment(
    loader=jinja2.FileSystemLoader(TEMPLATES_DIR),
    autoescape=True,
)
templates = Jinja2Templates(env=_env)


@router.get("/recepcao/agenda", dependencies=[Depends(somente_recepcao_ou_admin)])
def agenda_do_dia(
    request: Request,
    data: date = Query(default_factory=date.today),
    session: Session = Depends(get_session),
):
    inicio = datetime.combine(data, time.min)
    fim = datetime.combine(data, time.max)
    query = (
        select(Consulta)
        .where(Consulta.data_hora >= inicio, Consulta.data_hora <= fim)
        .order_by(Consulta.data_hora)
    )
    consultas_do_dia = session.exec(query).all()
    return templates.TemplateResponse(
        request=request,
        name="agenda.html",
        context={
            "consultas": consultas_do_dia,
            "data_referencia": data.strftime("%d/%m/%Y"),
        },
    )
