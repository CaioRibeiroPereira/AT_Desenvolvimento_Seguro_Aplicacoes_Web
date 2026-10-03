import hmac
from typing import Optional

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlmodel import Session, select

from app.auth.security import (
    DUMMY_HASH,
    create_access_token,
    create_client_token,
    verify_password,
)
from app.config import settings
from app.database import get_session
from app.models.client import Client
from app.models.user import Role, User
from app.rate_limit import limiter
from app.schemas.auth import Token

router = APIRouter(prefix="/auth", tags=["auth"])

_CREDENCIAIS_INVALIDAS = HTTPException(
    status.HTTP_401_UNAUTHORIZED,
    "Credenciais invalidas",
    headers={"WWW-Authenticate": "Bearer"},
)


@router.post("/login", response_model=Token)
@limiter.limit("5/minute")  # mais restrito que o padrao global (100/minute): alvo recorrente de forca bruta
def login(
    request: Request,
    form: OAuth2PasswordRequestForm = Depends(),
    mfa_code: Optional[str] = Form(default=None),
    session: Session = Depends(get_session),
) -> Token:
    user = session.exec(select(User).where(User.username == form.username)).first()
    # hash falso quando o usuario nao existe: iguala o tempo de resposta
    hash_alvo = user.hashed_password if user else DUMMY_HASH
    senha_ok = verify_password(form.password, hash_alvo)
    if user is None or not senha_ok:
        raise _CREDENCIAIS_INVALIDAS

    if user.role == Role.admin:
        if mfa_code is None or not hmac.compare_digest(mfa_code, settings.mfa_code):
            raise HTTPException(
                status.HTTP_401_UNAUTHORIZED,
                "Codigo MFA invalido ou ausente",
                headers={"WWW-Authenticate": "Bearer"},
            )

    return Token(access_token=create_access_token(user), token_type="bearer")


@router.post("/token", response_model=Token)
def client_credentials_token(
    grant_type: str = Form(...),
    client_id: str = Form(...),
    client_secret: str = Form(...),
    session: Session = Depends(get_session),
) -> Token:
    # fluxo Client Credentials (RFC 6749 4.4): sem usuario humano,
    # o proprio cliente (laboratorio) e o titular do token
    if grant_type != "client_credentials":
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "grant_type nao suportado")

    client = session.exec(select(Client).where(Client.client_id == client_id)).first()
    segredo_alvo = client.hashed_secret if client else DUMMY_HASH
    segredo_ok = verify_password(client_secret, segredo_alvo)
    if client is None or not segredo_ok:
        raise _CREDENCIAIS_INVALIDAS

    return Token(access_token=create_client_token(client), token_type="bearer")
