import base64
import json
from datetime import datetime, timedelta, timezone

import jwt as pyjwt
from fastapi.testclient import TestClient

from app.auth.security import ALGORITHM
from app.config import settings
from app.main import app
from tests.helpers import auth_header

client = TestClient(app)


def test_jwt_com_claims_adulteradas_e_rejeitado():
    # T-04: token valido, mas o payload foi trocado (role -> admin) sem reassinar
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
    # T-14 (parcial, nao corrigido de proposito - ver docs/12_devsecops.md):
    # 403 (existe, mas nao e seu) e 404 (nao existe) sao distinguiveis, o que
    # permite a um atacante autenticado mapear quais ids de consulta existem,
    # mesmo sem conseguir ler o conteudo. Risco residual, nao um teste de
    # regressao de algo corrigido.
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
