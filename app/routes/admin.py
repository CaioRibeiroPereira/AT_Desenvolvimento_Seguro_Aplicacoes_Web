from typing import List

from fastapi import APIRouter, Depends
from sqlmodel import Session, select

from app.auth.deps import require_roles
from app.database import get_session
from app.models.auditoria import AuditLog
from app.models.user import Role, User
from app.schemas.auth import UserRead

router = APIRouter(
    prefix="/admin",
    tags=["admin"],
    dependencies=[Depends(require_roles(Role.admin))],
)


@router.get("/usuarios", response_model=List[UserRead])
def listar_usuarios(session: Session = Depends(get_session)) -> List[User]:
    return session.exec(select(User)).all()


@router.get("/auditoria", response_model=List[AuditLog])
def listar_auditoria(session: Session = Depends(get_session)) -> List[AuditLog]:
    return session.exec(select(AuditLog).order_by(AuditLog.id)).all()
