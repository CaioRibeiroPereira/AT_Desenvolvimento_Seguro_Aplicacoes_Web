# API de Agendamento Clínico Seguro

API REST em FastAPI para agendamento de consultas médicas, com segurança de software aplicada em cada camada: autenticação JWT, RBAC com ownership, escopos OAuth2 para integração M2M, validação de entrada, CORS com allowlist, cabeçalhos de segurança, rate limiting e persistência via SQLModel.

Projeto da disciplina Desenvolvimento Seguro de Aplicações Web.

## Como rodar

```bash
python -m venv .venv
source .venv/Scripts/activate  # Windows (Git Bash)
pip install -r requirements.txt
cp .env.example .env  # preencher com valores proprios
uvicorn app.main:app --reload
```

Documentação interativa: `http://127.0.0.1:8000/docs`

## Testes

```bash
pytest -v
```

## Documentação

Decisões de segurança de cada exercício estão em `docs/`.
