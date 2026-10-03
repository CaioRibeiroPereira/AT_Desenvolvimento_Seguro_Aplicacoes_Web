import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlmodel import Session, select

from app.auth.security import decode_access_token
from app.database import get_session
from app.models.user import Role, User

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

_NAO_AUTENTICADO = HTTPException(
    status.HTTP_401_UNAUTHORIZED,
    "Token invalido ou expirado",
    headers={"WWW-Authenticate": "Bearer"},
)


def get_current_user(
    token: str = Depends(oauth2_scheme),
    session: Session = Depends(get_session),
) -> User:
    try:
        claims = decode_access_token(token)
    except jwt.PyJWTError:
        raise _NAO_AUTENTICADO
    if claims.get("token_type") != "user":
        raise _NAO_AUTENTICADO
    user = session.exec(select(User).where(User.username == claims["sub"])).first()
    if user is None:
        raise _NAO_AUTENTICADO
    return user


def require_roles(*roles: Role):
    def checker(user: User = Depends(get_current_user)) -> User:
        if user.role not in roles:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Acesso negado")
        return user

    return checker


def get_current_client(token: str = Depends(oauth2_scheme)) -> dict:
    try:
        claims = decode_access_token(token)
    except jwt.PyJWTError:
        raise _NAO_AUTENTICADO
    if claims.get("token_type") != "client_credentials":
        raise _NAO_AUTENTICADO
    return claims


def require_scope(scope: str):
    def checker(claims: dict = Depends(get_current_client)) -> dict:
        escopos = claims.get("scope", "").split()
        if scope not in escopos:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Escopo insuficiente")
        return claims

    return checker
