import base64
import json
from datetime import datetime, timedelta, timezone

import jwt as pyjwt
from fastapi.testclient import TestClient
from sqlmodel import Session

from app.auth.security import ALGORITHM
from app.config import settings
from app.main import app
from app.models.consulta import Consulta
from tests.conftest import test_engine
from tests.helpers import auth_header

client = TestClient(app)


def test_jwt_com_claims_adulteradas_e_rejeitado():
    # T-04: token válido, mas o payload foi trocado (role virou admin) sem reassinar
    token = auth_header(client, "dr_silva")["Authorization"].split(" ")[1]
    cabecalho, payload, assinatura = token.split(".")
    dados = json.loads(base64.urlsafe_b64decode(payload + "=="))
    dados["role"] = "admin"
    payload_adulterado = (
        base64.urlsafe_b64encode(json.dumps(dados).encode()).decode().rstrip("=")
    )
    token_adulterado = f"{cabecalho}.{payload_adulterado}.{assinatura}"

    resposta = client.get(
        "/admin/usuarios", headers={"Authorization": f"Bearer {token_adulterado}"}
    )
    assert resposta.status_code == 401


def test_jwt_expirado_e_rejeitado():
    # T-04: token assinado corretamente, mas com exp no passado
    agora = datetime.now(timezone.utc)
    claims = {
        "sub": "dr_silva",
        "role": "profissional",
        "token_type": "user",
        "iat": agora - timedelta(hours=1),
        "exp": agora - timedelta(minutes=1),
    }
    token_expirado = pyjwt.encode(claims, settings.secret_key, algorithm=ALGORITHM)

    resposta = client.get(
        "/consultas", headers={"Authorization": f"Bearer {token_expirado}"}
    )
    assert resposta.status_code == 401


def test_risco_residual_id_inexistente_e_id_de_outro_dono_tem_respostas_diferentes():
    # T-14 (parcial, não corrigido de proposito - ver docs/12_devsecops.md):
    # 403 (existe, mas não e seu) e 404 (não existe) são distinguíveis, o que
    # permite a um atacante autenticado mapear quais ids de consulta existem,
    # mesmo sem conseguir ler o conteúdo. Risco residual, não um teste de
    # regressão de algo corrigido.
    consulta_id = client.post(
        "/consultas",
        json={
            "paciente_id": 70,
            "profissional_id": 10,
            "data_hora": "2026-12-10T10:00:00",
            "motivo": "Consulta para teste de enumeracao",
        },
        headers=auth_header(client, "dr_silva"),
    ).json()["id"]

    outro = auth_header(client, "dr_souza")
    existe_mas_nao_e_dono = client.get(f"/consultas/{consulta_id}", headers=outro)
    nao_existe = client.get("/consultas/999999", headers=outro)

    assert existe_mas_nao_e_dono.status_code == 403
    assert nao_existe.status_code == 404


CONSULTA_BASE = {
    "paciente_id": 80,
    "profissional_id": 10,
    "data_hora": "2026-12-11T10:00:00",
    "motivo": "Consulta para teste de escrita",
}


def _criar_consulta_do_dr_silva() -> int:
    return client.post(
        "/consultas", json=CONSULTA_BASE, headers=auth_header(client, "dr_silva")
    ).json()["id"]


def test_token_forjado_com_outra_chave_e_rejeitado():
    # T-04 / MC-07: JWT com claims válidas, mas assinado com chave que o servidor não conhece
    claims = {
        "sub": "admin",
        "role": "admin",
        "token_type": "user",
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(minutes=5),
    }
    token_forjado = pyjwt.encode(claims, "chave-do-atacante-com-mais-de-32-chars", algorithm=ALGORITHM)

    resposta = client.get("/admin/usuarios", headers={"Authorization": f"Bearer {token_forjado}"})
    assert resposta.status_code == 401


def test_profissional_nao_altera_nem_apaga_consulta_de_outro_profissional():
    # T-10 / MC-01: escrita (PUT e DELETE) em consulta alheia, não apenas PATCH
    cid = _criar_consulta_do_dr_silva()
    outro = auth_header(client, "dr_souza")

    assert client.put(f"/consultas/{cid}", json=CONSULTA_BASE, headers=outro).status_code == 403
    assert client.delete(f"/consultas/{cid}", headers=outro).status_code == 403


def test_recepcionista_nao_altera_nem_apaga_consulta():
    # T-13 / MC-05: papel sem permissão de escrita nas rotas clínicas
    cid = _criar_consulta_do_dr_silva()
    recepcao = auth_header(client, "recepcao")

    assert client.put(f"/consultas/{cid}", json=CONSULTA_BASE, headers=recepcao).status_code == 403
    assert client.patch(f"/consultas/{cid}", json={"status": "cancelada"}, headers=recepcao).status_code == 403
    assert client.delete(f"/consultas/{cid}", headers=recepcao).status_code == 403


def test_mass_assignment_em_patch_nao_altera_campo_interno():
    # T-08 / MC-06: campo de auditoria enviado no corpo e rejeitado; o valor original permanece
    cid = _criar_consulta_do_dr_silva()
    dono = auth_header(client, "dr_silva")

    resposta = client.patch(
        f"/consultas/{cid}", json={"created_by": "atacante"}, headers=dono
    )
    assert resposta.status_code == 422
    with Session(test_engine) as session:
        assert session.get(Consulta, cid).created_by == "dr_silva"


def test_escrita_sem_token_retorna_401():
    # MC-01: rotas de escrita não aceitam requisição anonima
    cid = _criar_consulta_do_dr_silva()

    assert client.post("/consultas", json=CONSULTA_BASE).status_code == 401
    assert client.put(f"/consultas/{cid}", json=CONSULTA_BASE).status_code == 401
    assert client.patch(f"/consultas/{cid}", json={"status": "cancelada"}).status_code == 401
    assert client.delete(f"/consultas/{cid}").status_code == 401


def test_profissional_nao_cria_consulta_para_outro_profissional():
    # T-10 / MC-01: criação com profissional_id alheio ao usuário autenticado
    resposta = client.post(
        "/consultas",
        json={**CONSULTA_BASE, "profissional_id": 20},
        headers=auth_header(client, "dr_silva"),
    )
    assert resposta.status_code == 403
