from datetime import date

from fastapi.testclient import TestClient

from app.main import app
from tests.helpers import auth_header, lab_auth_header

client = TestClient(app)


def test_laboratorio_obtem_token_com_credenciais_validas():
    headers = lab_auth_header(client)
    assert "Authorization" in headers


def test_laboratorio_com_segredo_errado_e_negado():
    resposta = client.post(
        "/auth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": "lab-teste",
            "client_secret": "segredo-errado",
        },
    )
    assert resposta.status_code == 401


def test_token_do_laboratorio_acessa_slots():
    hoje = date.today().isoformat()
    resposta = client.get(f"/slots?data={hoje}", headers=lab_auth_header(client))
    assert resposta.status_code == 200


def test_token_do_laboratorio_e_negado_em_rota_clinica():
    resposta = client.get("/consultas", headers=lab_auth_header(client))
    assert resposta.status_code == 401


def test_token_de_profissional_e_negado_em_slots():
    hoje = date.today().isoformat()
    resposta = client.get(
        f"/slots?data={hoje}", headers=auth_header(client, "dr_silva")
    )
    assert resposta.status_code == 401


def test_slots_nao_expoe_dado_de_paciente():
    hoje = date.today().isoformat()
    client.post(
        "/consultas",
        json={
            "paciente_id": 99,
            "profissional_id": 10,
            "data_hora": f"{hoje}T09:00:00",
            "motivo": "Dado confidencial do paciente",
        },
        headers=auth_header(client, "dr_silva"),
    )
    resposta = client.get(f"/slots?data={hoje}", headers=lab_auth_header(client))
    assert resposta.status_code == 200
    corpo = resposta.text
    assert "paciente_id" not in corpo
    assert "Dado confidencial" not in corpo
