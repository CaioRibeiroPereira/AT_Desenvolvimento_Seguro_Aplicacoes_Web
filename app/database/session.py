from sqlmodel import Session, SQLModel, create_engine

from app.config import settings

# check_same_thread so se aplica ao SQLite (permite a mesma conexao entre
# as threads do uvicorn); credenciais/URL vem do .env via BaseSettings,
# nunca hardcoded aqui.
connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}
engine = create_engine(settings.database_url, connect_args=connect_args)


def get_session():
    with Session(engine) as session:
        yield session


def init_db() -> None:
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        from app.database.clients import seed_clients
        from app.database.users import seed_users

        seed_users(session)
        seed_clients(session)
