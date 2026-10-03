from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlmodel import Session

from app.auth.deps import get_current_user, require_roles
from app.auth.ownership import (
    query_visiveis,
    verificar_ownership_escrita,
    verificar_ownership_leitura,
    verificar_profissional_do_payload,
)
from app.auditoria import registrar, snapshot
from app.database import get_session
from app.models.consulta import Consulta
from app.models.user import Role, User
from app.schemas.consulta import ConsultaCreate, ConsultaRead, ConsultaUpdate

router = APIRouter(prefix="/consultas", tags=["consultas"])

somente_profissional_ou_admin = require_roles(Role.profissional, Role.admin)


@router.get("", response_model=List[ConsultaRead])
def listar_consultas(
    user: User = Depends(get_current_user),
    session: Session = Depends(get_session),
) -> List[Consulta]:
    return session.exec(query_visiveis(user)).all()


@router.get("/{consulta_id}", response_model=ConsultaRead)
def obter_consulta(
    consulta_id: int,
    user: User = Depends(get_current_user),
    session: Session = Depends(get_session),
) -> Consulta:
    consulta = session.get(Consulta, consulta_id)
    if consulta is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Consulta nao encontrada")
    verificar_ownership_leitura(user, consulta)
    return consulta


@router.post("", response_model=ConsultaRead, status_code=status.HTTP_201_CREATED)
def criar_consulta(
    payload: ConsultaCreate,
    user: User = Depends(somente_profissional_ou_admin),
    session: Session = Depends(get_session),
) -> Consulta:
    verificar_profissional_do_payload(user, payload.profissional_id)
    consulta = Consulta(created_by=user.username, internal_notes=None, **payload.model_dump())
    session.add(consulta)
    session.flush()
    registrar(session, user, "criar", consulta.id, None, snapshot(consulta))
    session.commit()
    session.refresh(consulta)
    return consulta


@router.put("/{consulta_id}", response_model=ConsultaRead)
def atualizar_consulta(
    consulta_id: int,
    payload: ConsultaCreate,
    user: User = Depends(somente_profissional_ou_admin),
    session: Session = Depends(get_session),
) -> Consulta:
    consulta = session.get(Consulta, consulta_id)
    if consulta is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Consulta nao encontrada")
    verificar_ownership_escrita(user, consulta)
    verificar_profissional_do_payload(user, payload.profissional_id)
    antes = snapshot(consulta)
    for campo, valor in payload.model_dump().items():
        setattr(consulta, campo, valor)
    registrar(session, user, "atualizar", consulta_id, antes, snapshot(consulta))
    session.add(consulta)
    session.commit()
    session.refresh(consulta)
    return consulta


@router.patch("/{consulta_id}", response_model=ConsultaRead)
def atualizar_consulta_parcial(
    consulta_id: int,
    payload: ConsultaUpdate,
    user: User = Depends(somente_profissional_ou_admin),
    session: Session = Depends(get_session),
) -> Consulta:
    consulta = session.get(Consulta, consulta_id)
    if consulta is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Consulta nao encontrada")
    verificar_ownership_escrita(user, consulta)
    antes = snapshot(consulta)
    for campo, valor in payload.model_dump(exclude_unset=True).items():
        setattr(consulta, campo, valor)
    registrar(session, user, "atualizar_parcial", consulta_id, antes, snapshot(consulta))
    session.add(consulta)
    session.commit()
    session.refresh(consulta)
    return consulta


@router.delete("/{consulta_id}", status_code=status.HTTP_204_NO_CONTENT)
def deletar_consulta(
    consulta_id: int,
    user: User = Depends(somente_profissional_ou_admin),
    session: Session = Depends(get_session),
) -> None:
    consulta = session.get(Consulta, consulta_id)
    if consulta is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Consulta nao encontrada")
    verificar_ownership_escrita(user, consulta)
    registrar(session, user, "deletar", consulta_id, snapshot(consulta), None)
    session.delete(consulta)
    session.commit()
