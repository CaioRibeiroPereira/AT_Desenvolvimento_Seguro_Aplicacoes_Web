from datetime import date

from fastapi.testclient import TestClient

from app.main import app
from tests.helpers import auth_header

client = TestClient(app)


def _criar_consulta_de_dr_silva() -> int:
    resposta = client.post(
        "/consultas",
        json={
            "paciente_id": 50,
            "profissional_id": 10,
            "data_hora": "2026-12-05T10:00:00",
            "motivo": "Consulta confidencial do paciente",
        },
        headers=auth_header(client, "dr_silva"),
    )
    assert resposta.status_code == 201
    return resposta.json()["id"]


def test_bola_corrigida_profissional_nao_le_consulta_de_outro():
    consulta_id = _criar_consulta_de_dr_silva()
    resposta = client.get(
        f"/consultas/{consulta_id}", headers=auth_header(client, "dr_souza")
    )
    assert resposta.status_code == 403


def test_bola_corrigida_listagem_filtra_por_dono():
    _criar_consulta_de_dr_silva()
    resposta = client.get("/consultas", headers=auth_header(client, "dr_souza"))
    assert resposta.status_code == 200
    ids_profissional = {c["profissional_id"] for c in resposta.json()}
    assert 10 not in ids_profissional


def test_recepcionista_e_admin_continuam_lendo_qualquer_consulta():
    consulta_id = _criar_consulta_de_dr_silva()
    for username in ("recepcao", "admin"):
        resposta = client.get(
            f"/consultas/{consulta_id}", headers=auth_header(client, username)
        )
        assert resposta.status_code == 200


def test_extra_forbid_rejeita_campo_nao_declarado():
    resposta = client.post(
        "/consultas",
        json={
            "paciente_id": 60,
            "profissional_id": 10,
            "data_hora": "2026-12-06T10:00:00",
            "motivo": "Consulta de rotina",
            "created_by": "invasor",
        },
        headers=auth_header(client, "dr_silva"),
    )
    assert resposta.status_code == 422


def test_motivo_com_tag_html_e_rejeitado_na_entrada():
    resposta = client.post(
        "/consultas",
        json={
            "paciente_id": 61,
            "profissional_id": 10,
            "data_hora": "2026-12-06T11:00:00",
            "motivo": "<script>alert(1)</script>",
        },
        headers=auth_header(client, "dr_silva"),
    )
    assert resposta.status_code == 422


def test_agenda_exige_autenticacao():
    hoje = date.today().isoformat()
    assert client.get(f"/recepcao/agenda?data={hoje}").status_code == 401


def test_agenda_bloqueia_profissional_e_libera_recepcao():
    hoje = date.today().isoformat()
    bloqueado = client.get(
        f"/recepcao/agenda?data={hoje}", headers=auth_header(client, "dr_silva")
    )
    assert bloqueado.status_code == 403

    liberado = client.get(
        f"/recepcao/agenda?data={hoje}", headers=auth_header(client, "recepcao")
    )
    assert liberado.status_code == 200
