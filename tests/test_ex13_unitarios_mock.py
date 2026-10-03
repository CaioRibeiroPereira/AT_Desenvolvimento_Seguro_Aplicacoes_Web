from unittest.mock import patch

import jwt
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.auth.deps import get_current_user
from app.main import app
from app.models.user import Role, User
from app.schemas.consulta import ConsultaCreate
from tests.helpers import auth_header

client = TestClient(app)


# entrada: unidade pura do schema, sem precisar da API nem do banco
def test_consulta_create_rejeita_campo_extra_isoladamente():
    with pytest.raises(ValidationError):
        ConsultaCreate(
            paciente_id=1,
            profissional_id=10,
            data_hora="2026-12-01T10:00:00",
            motivo="Consulta valida",
            created_by="invasor",
        )


def test_consulta_create_rejeita_motivo_com_tag_html_isoladamente():
    with pytest.raises(ValidationError):
        ConsultaCreate(
            paciente_id=1,
            profissional_id=10,
            data_hora="2026-12-01T10:00:00",
            motivo="<script>alert(1)</script>",
        )


# entrada: mocka verify_password para isolar a rota de login do bcrypt real
def test_login_rejeitado_quando_verify_password_mockado_falha():
    with patch("app.routes.auth.verify_password", return_value=False):
        resposta = client.post(
            "/auth/login", data={"username": "dr_silva", "password": "Silva@2026"}
        )
    assert resposta.status_code == 401


def test_login_aceito_quando_verify_password_mockado_sucesso():
    # mesmo com senha "errada", o mock controla o resultado da verificação:
    # prova que a rota confia no retorno da função, não recalcula por conta propria
    with patch("app.routes.auth.verify_password", return_value=True):
        resposta = client.post(
            "/auth/login", data={"username": "dr_silva", "password": "qualquer-coisa"}
        )
    assert resposta.status_code == 200


# autorização: mocka decode_access_token para isolar a dependência de auth do JWT real
def test_rota_protegida_nega_quando_decode_access_token_mockado_falha():
    with patch("app.auth.deps.decode_access_token", side_effect=jwt.PyJWTError):
        resposta = client.get(
            "/consultas", headers={"Authorization": "Bearer qualquer-coisa"}
        )
    assert resposta.status_code == 401


# autorização: mocka o usuário autenticado via dependency_override do FastAPI,
# isolando a checagem de papel (require_roles) de login/JWT/banco reais
def test_admin_aceita_usuario_mockado_via_dependency_override():
    usuario_fake = User(id=99, username="fake", hashed_password="x", role=Role.admin)
    app.dependency_overrides[get_current_user] = lambda: usuario_fake
    try:
        resposta = client.get(
            "/admin/usuarios", headers={"Authorization": "Bearer x"}
        )
    finally:
        del app.dependency_overrides[get_current_user]
    assert resposta.status_code == 200


def test_admin_nega_usuario_mockado_sem_papel_admin():
    usuario_fake = User(
        id=1, username="fake", hashed_password="x", role=Role.recepcionista
    )
    app.dependency_overrides[get_current_user] = lambda: usuario_fake
    try:
        resposta = client.get(
            "/admin/usuarios", headers={"Authorization": "Bearer x"}
        )
    finally:
        del app.dependency_overrides[get_current_user]
    assert resposta.status_code == 403


def test_sanity_login_real_ainda_funciona_sem_mock():
    # confirma que os mocks acima não vazaram estado entre testes
    headers = auth_header(client, "dr_silva")
    assert "Authorization" in headers
