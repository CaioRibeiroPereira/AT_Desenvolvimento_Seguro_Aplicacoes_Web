from fastapi.testclient import TestClient

from app.main import app
from tests.helpers import SENHAS, auth_header, codigo_mfa

client = TestClient(app)


def test_usuario_sem_papel_admin_e_bloqueado_na_rota_admin():
    for username in ("recepcao", "dr_silva"):
        resposta = client.get("/admin/usuarios", headers=auth_header(client, username))
        assert resposta.status_code == 403


def test_rota_admin_sem_token_retorna_401():
    assert client.get("/admin/usuarios").status_code == 401


def test_admin_com_mfa_acessa_rota_admin_sem_expor_hash():
    resposta = client.get("/admin/usuarios", headers=auth_header(client, "admin"))
    assert resposta.status_code == 200
    assert "hashed_password" not in resposta.text


def test_login_admin_exige_mfa():
    dados = {"username": "admin", "password": SENHAS["admin"]}
    assert client.post("/auth/login", data=dados).status_code == 401
    assert client.post("/auth/login", data={**dados, "mfa_code": "000000"}).status_code == 401
    assert client.post("/auth/login", data={**dados, "mfa_code": codigo_mfa()}).status_code == 200


def test_login_com_senha_errada_ou_usuario_inexistente_da_mesma_resposta():
    errada = client.post("/auth/login", data={"username": "dr_silva", "password": "x"})
    inexistente = client.post("/auth/login", data={"username": "ninguem", "password": "x"})
    assert errada.status_code == inexistente.status_code == 401
    assert errada.json() == inexistente.json()


def test_profissional_nao_altera_consulta_de_outro_profissional():
    dono = auth_header(client, "dr_silva")
    consulta = client.post(
        "/consultas",
        json={
            "paciente_id": 7,
            "profissional_id": 10,
            "data_hora": "2026-12-01T10:00:00",
            "motivo": "Consulta do dr silva",
        },
        headers=dono,
    ).json()

    outro = auth_header(client, "dr_souza")
    resposta = client.patch(
        f"/consultas/{consulta['id']}", json={"status": "cancelada"}, headers=outro
    )
    assert resposta.status_code == 403


def test_recepcionista_nao_cria_consulta():
    resposta = client.post(
        "/consultas",
        json={
            "paciente_id": 1,
            "profissional_id": 10,
            "data_hora": "2026-12-01T10:00:00",
            "motivo": "Tentativa da recepcao",
        },
        headers=auth_header(client, "recepcao"),
    )
    assert resposta.status_code == 403
