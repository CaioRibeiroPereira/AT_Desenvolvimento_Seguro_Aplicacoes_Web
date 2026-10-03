from sqlmodel import Session, select

from app.auth.security import hash_password
from app.config import settings
from app.models.client import Client


def seed_clients(session: Session) -> None:
    if session.exec(select(Client)).first():
        return
    session.add(
        Client(
            client_id=settings.lab_client_id,
            hashed_secret=hash_password(settings.lab_client_secret),
            scopes="slots:read",
        )
    )
    session.commit()
