from fastapi.testclient import TestClient

from app.main import app
from tests.helpers import auth_header

client = TestClient(app)


def test_criar_e_obter_consulta_com_sucesso():
    headers = auth_header(client, "dr_silva")
    payload = {
        "paciente_id": 1,
        "profissional_id": 10,
        "data_hora": "2026-10-01T14:30:00",
        "motivo": "Consulta de rotina",
    }

    resposta_post = client.post("/consultas", json=payload, headers=headers)
    assert resposta_post.status_code == 201

    corpo = resposta_post.json()
    assert corpo["paciente_id"] == payload["paciente_id"]
    assert corpo["status"] == "agendada"
    consulta_id = corpo["id"]

    resposta_get = client.get(f"/consultas/{consulta_id}", headers=headers)
    assert resposta_get.status_code == 200
    assert resposta_get.json()["motivo"] == "Consulta de rotina"
