from sqlmodel import Session, select

from app.auth.security import hash_password
from app.config import settings
from app.models.user import Role, User


def seed_users(session: Session) -> None:
    if session.exec(select(User)).first():
        return
    contas = [
        ("admin", settings.seed_admin_password, Role.admin, None),
        ("dr_silva", settings.seed_dr_silva_password, Role.profissional, 10),
        ("dr_souza", settings.seed_dr_souza_password, Role.profissional, 20),
        ("recepcao", settings.seed_recepcionista_password, Role.recepcionista, None),
    ]
    for username, senha, role, prof_id in contas:
        session.add(
            User(
                username=username,
                hashed_password=hash_password(senha),
                role=role,
                profissional_id=prof_id,
            )
        )
    session.commit()
