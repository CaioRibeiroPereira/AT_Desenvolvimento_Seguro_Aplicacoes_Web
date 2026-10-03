from fastapi.testclient import TestClient

from app.main import app
from app.rate_limit import limiter

client = TestClient(app)


def test_headers_de_seguranca_presentes_em_toda_resposta():
    resposta = client.get("/health")
    assert resposta.headers["x-frame-options"] == "DENY"
    assert resposta.headers["x-content-type-options"] == "nosniff"
    assert "max-age=31536000" in resposta.headers["strict-transport-security"]


def test_cors_rejeita_origem_fora_da_allowlist():
    resposta = client.get(
        "/health", headers={"Origin": "http://site-malicioso.test"}
    )
    assert "access-control-allow-origin" not in resposta.headers


def test_cors_libera_origem_da_allowlist():
    resposta = client.get("/health", headers={"Origin": "http://localhost:3000"})
    assert resposta.headers["access-control-allow-origin"] == "http://localhost:3000"


def test_rate_limit_diferenciado_no_login():
    limiter.enabled = True
    try:
        respostas = [
            client.post(
                "/auth/login", data={"username": "dr_silva", "password": "errada"}
            )
            for _ in range(6)
        ]
    finally:
        limiter.enabled = False

    codigos = [r.status_code for r in respostas]
    assert codigos[:5] == [401, 401, 401, 401, 401]
    assert codigos[5] == 429
