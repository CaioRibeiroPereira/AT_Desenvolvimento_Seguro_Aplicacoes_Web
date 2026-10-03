from fastapi import HTTPException, status
from sqlmodel import select

from app.models.consulta import Consulta
from app.models.user import Role, User


def _e_dono(user: User, consulta: Consulta) -> bool:
    return user.role == Role.profissional and consulta.profissional_id == user.profissional_id


def verificar_ownership_leitura(user: User, consulta: Consulta) -> None:
    if user.role in (Role.admin, Role.recepcionista) or _e_dono(user, consulta):
        return
    raise HTTPException(status.HTTP_403_FORBIDDEN, "Acesso negado")


def verificar_ownership_escrita(user: User, consulta: Consulta) -> None:
    if user.role == Role.admin or _e_dono(user, consulta):
        return
    raise HTTPException(status.HTTP_403_FORBIDDEN, "Acesso negado")


def query_visiveis(user: User):
    # where() do SQLModel gera SQL parametrizado; nunca concatenamos o valor na string.
    query = select(Consulta)
    if user.role == Role.profissional:
        query = query.where(Consulta.profissional_id == user.profissional_id)
    return query
