from datetime import datetime, timedelta, timezone

import bcrypt
import jwt

from app.config import settings
from app.models.client import Client
from app.models.user import User

ALGORITHM = "HS256"
MAX_PASSWORD_BYTES = 72
DUMMY_HASH = bcrypt.hashpw(b"dummy", bcrypt.gensalt()).decode()


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, hashed: str) -> bool:
    raw = password.encode()
    if len(raw) > MAX_PASSWORD_BYTES:
        return False
    return bcrypt.checkpw(raw, hashed.encode())


def create_access_token(user: User) -> str:
    agora = datetime.now(timezone.utc)
    claims = {
        "sub": user.username,
        "role": user.role.value,
        "token_type": "user",
        "iat": agora,
        "exp": agora + timedelta(minutes=settings.access_token_expire_minutes),
    }
    return jwt.encode(claims, settings.secret_key, algorithm=ALGORITHM)


def create_client_token(client: Client) -> str:
    agora = datetime.now(timezone.utc)
    claims = {
        "sub": client.client_id,
        "token_type": "client_credentials",
        "scope": client.scopes,
        "iat": agora,
        "exp": agora + timedelta(minutes=settings.client_token_expire_minutes),
    }
    return jwt.encode(claims, settings.secret_key, algorithm=ALGORITHM)


def decode_access_token(token: str) -> dict:
    # algoritmo fixo na lista: rejeita tokens "alg: none" ou trocados
    return jwt.decode(
        token,
        settings.secret_key,
        algorithms=[ALGORITHM],
        options={"require": ["exp", "sub"]},
    )
