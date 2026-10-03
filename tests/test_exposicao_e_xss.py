from datetime import date, datetime, time

from fastapi.testclient import TestClient
from sqlmodel import Session

from app.main import app
from app.models.consulta import Consulta
from tests.conftest import test_engine
from tests.helpers import auth_header

client = TestClient(app)


def test_response_model_nao_expoe_campos_internos_de_auditoria():
    payload = {
        "paciente_id": 2,
        "profissional_id": 20,
        "data_hora": "2026-11-05T09:00:00",
        "motivo": "Retorno pos-cirurgico",
    }

    resposta = client.post(
        "/consultas", json=payload, headers=auth_header(client, "dr_souza")
    )
    assert resposta.status_code == 201

    corpo = resposta.json()
    assert "created_by" not in corpo
    assert "internal_notes" not in corpo
    assert corpo["motivo"] == "Retorno pos-cirurgico"


def test_agenda_html_escapa_payload_xss_ja_armazenado():
    # simula um dado malicioso que chegou ao armazenamento por outra via
    # (ex.: migração de dados antiga), sem passar pela validação da API,
    # para provar que o auto-escape do Jinja2 continua sendo a última
    # linha de defesa mesmo quando a validação de entrada não e o único caminho.
    hoje = date.today().isoformat()
    with Session(test_engine) as session:
        session.add(
            Consulta(
                paciente_id=4,
                profissional_id=40,
                data_hora=datetime.combine(date.today(), time(16, 0)),
                motivo="<script>document.location='http://evil.test'</script>",
                created_by="migracao",
            )
        )
        session.commit()

    resposta_agenda = client.get(
        f"/recepcao/agenda?data={hoje}", headers=auth_header(client, "recepcao")
    )
    assert resposta_agenda.status_code == 200
    html = resposta_agenda.text
    assert "<script>" not in html
    assert "&lt;script&gt;" in html
