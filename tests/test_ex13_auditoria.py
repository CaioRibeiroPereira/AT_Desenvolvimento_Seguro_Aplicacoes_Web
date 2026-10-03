import json

from fastapi.testclient import TestClient

from app.main import app
from tests.helpers import auth_header

client = TestClient(app)

NOVA_CONSULTA = {
    "paciente_id": 42,
    "profissional_id": 10,
    "data_hora": "2026-12-01T10:00:00",
    "motivo": "Consulta para auditoria",
}


def _registros_da_consulta(consulta_id: int) -> list[dict]:
    todos = client.get("/admin/auditoria", headers=auth_header(client, "admin")).json()
    return [r for r in todos if r["consulta_id"] == consulta_id]


def test_criacao_alteracao_e_exclusao_geram_registros_de_auditoria():
    dono = auth_header(client, "dr_silva")
    consulta = client.post("/consultas", json=NOVA_CONSULTA, headers=dono).json()
    cid = consulta["id"]

    client.patch(f"/consultas/{cid}", json={"status": "confirmada"}, headers=dono)
    client.delete(f"/consultas/{cid}", headers=dono)

    registros = _registros_da_consulta(cid)
    assert [r["acao"] for r in registros] == ["criar", "atualizar_parcial", "deletar"]
    assert {r["usuario"] for r in registros} == {"dr_silva"}


def test_alteracao_registra_valor_antes_e_depois_do_campo_modificado():
    dono = auth_header(client, "dr_silva")
    cid = client.post("/consultas", json=NOVA_CONSULTA, headers=dono).json()["id"]

    client.patch(f"/consultas/{cid}", json={"status": "cancelada"}, headers=dono)

    alteracao = _registros_da_consulta(cid)[-1]
    assert alteracao["acao"] == "atualizar_parcial"
    assert json.loads(alteracao["alteracoes"]) == {
        "status": {"antes": "agendada", "depois": "cancelada"}
    }


def test_registro_de_auditoria_nao_e_removido_quando_consulta_e_apagada():
    dono = auth_header(client, "dr_silva")
    cid = client.post("/consultas", json=NOVA_CONSULTA, headers=dono).json()["id"]
    client.delete(f"/consultas/{cid}", headers=dono)

    assert _registros_da_consulta(cid)[-1]["acao"] == "deletar"


def test_auditoria_so_e_acessivel_para_admin():
    resposta = client.get("/admin/auditoria", headers=auth_header(client, "recepcao"))
    assert resposta.status_code == 403
