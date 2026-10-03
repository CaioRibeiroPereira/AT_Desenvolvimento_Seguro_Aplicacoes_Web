import os

from tests import helpers
from tests.helpers import LAB_CLIENT_ID, LAB_CLIENT_SECRET, SENHAS

os.environ["SECRET_KEY"] = "chave-de-teste-com-mais-de-32-caracteres-xxxxxxxx"
os.environ["SEED_ADMIN_PASSWORD"] = SENHAS["admin"]
os.environ["SEED_DR_SILVA_PASSWORD"] = SENHAS["dr_silva"]
os.environ["SEED_DR_SOUZA_PASSWORD"] = SENHAS["dr_souza"]
os.environ["SEED_RECEPCIONISTA_PASSWORD"] = SENHAS["recepcao"]
os.environ["LAB_CLIENT_ID"] = LAB_CLIENT_ID
os.environ["LAB_CLIENT_SECRET"] = LAB_CLIENT_SECRET
os.environ["DATABASE_URL"] = "sqlite://"  # nao usado de fato: os testes usam test_engine abaixo

from sqlalchemy.pool import StaticPool  # noqa: E402
from sqlmodel import Session, SQLModel, create_engine, select  # noqa: E402

from app.database import get_session  # noqa: E402
from app.database.clients import seed_clients  # noqa: E402
from app.database.users import seed_users  # noqa: E402
from app.main import app  # noqa: E402
from app.models.user import Role, User  # noqa: E402

# StaticPool: uma única conexão sqlite em memória compartilhada por todo o
# processo de teste (sem isso, cada Session veria um banco vazio diferente).
test_engine = create_engine(
    "sqlite://",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
SQLModel.metadata.create_all(test_engine)


def _override_get_session():
    with Session(test_engine) as session:
        yield session


app.dependency_overrides[get_session] = _override_get_session

with Session(test_engine) as _session:
    seed_users(_session)
    seed_clients(_session)
    admin = _session.exec(select(User).where(User.role == Role.admin)).one()
    helpers.MFA_SECRET_ADMIN = admin.mfa_secret

# o rate limit do login é testado à parte (test_ex10_hardening.py); nos
# demais testes ele só atrapalharia, pois fazem login repetidas vezes.
from app.rate_limit import limiter  # noqa: E402

limiter.enabled = False
