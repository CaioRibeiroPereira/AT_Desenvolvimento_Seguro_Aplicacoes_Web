# Exercício 8: Identificação de vulnerabilidades OWASP Top 10

Três padrões vulneráveis, de categorias distintas, encontrados lendo o código atual.

## Finding 1: BOLA em `GET /consultas/{id}` e `GET /consultas`

**Categoria:** API1:2023 Broken Object Level Authorization (OWASP API Security Top 10), equivalente a A01:2021 Broken Access Control no OWASP Top 10 geral.

**Código (`app/routes/consultas.py`):**
```python
@router.get("/{consulta_id}", response_model=ConsultaRead)
def obter_consulta(
    consulta_id: int,
    user: User = Depends(get_current_user),
    db: Dict[int, Consulta] = Depends(get_db),
) -> Consulta:
    consulta = db.get(consulta_id)
    if consulta is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Consulta nao encontrada")
    return consulta
```

A dependência é só `get_current_user`: exige estar logado, mas não verifica se a consulta pertence ao usuário. `GET /consultas` (lista completa) tem o mesmo problema.

**Como explorar:** um profissional autenticado troca o id na URL e lê a consulta de um paciente que não é dele.

```bash
# dr_silva cria uma consulta de um paciente dele (id retornado: 1)
# dr_souza, outro profissional sem nenhuma relacao com essa consulta, le pelo id
curl -s http://127.0.0.1:8000/consultas/1 -H "Authorization: Bearer <token de dr_souza>"
```

Confirmado neste ambiente: `dr_souza` recebeu `200` e o `motivo` completo da consulta de um paciente de `dr_silva`:
```json
{"id":1,"paciente_id":1,"profissional_id":10,"data_hora":"2026-11-10T09:00:00","motivo":"Dado sensivel do paciente de dr_silva","status":"agendada"}
```

**Por que é grave aqui:** expõe dado de saúde de um paciente a um profissional que nunca o atendeu, sem precisar de nenhuma falha de senha ou token. Só é preciso estar autenticado com qualquer conta.

## Finding 2: Sem rate limiting no login

**Categoria:** A07:2021 Identification and Authentication Failures.

**Código (`app/routes/auth.py`):**
```python
@router.post("/login", response_model=Token)
def login(
    form: OAuth2PasswordRequestForm = Depends(),
    mfa_code: Optional[str] = Form(default=None),
    users: Dict[str, User] = Depends(get_users_db),
) -> Token:
    user = users.get(form.username)
    hash_alvo = user.hashed_password if user else DUMMY_HASH
    senha_ok = verify_password(form.password, hash_alvo)
    if user is None or not senha_ok:
        raise _CREDENCIAIS_INVALIDAS
    ...
```

Não existe nenhum limite de tentativas por IP ou por usuário. A verificação de senha com `bcrypt` já é lenta por natureza, mas nada impede uma varredura automatizada de milhares de tentativas.

**Como explorar:** um script tenta repetidamente `POST /auth/login` com o mesmo `username` e senhas diferentes, sem nunca ser bloqueado.

```bash
for senha in 123456 admin123 Senha@2026 Silva@2026; do
  curl -s -o /dev/null -w "%{http_code}\n" -X POST http://127.0.0.1:8000/auth/login \
    -d "username=dr_silva&password=$senha"
done
```

Todas as tentativas retornam resposta normal (200 ou 401), nenhuma é bloqueada por volume.

**Por que é grave aqui:** a conta comprometida pode ser de um profissional com acesso a dados de saúde, ou, pior, a conta admin.

## Finding 3: Ausência de cabeçalhos de segurança HTTP

**Categoria:** A05:2021 Security Misconfiguration.

**Código (`app/main.py`):**
```python
app = FastAPI(
    title="API de Agendamento Clinico",
    description="API REST para agendamento de consultas medicas.",
    version="0.1.0",
)

app.include_router(auth.router)
app.include_router(admin.router)
app.include_router(consultas.router)
app.include_router(recepcao.router)
app.include_router(slots.router)
```

Não há nenhum middleware configurado. Nenhuma resposta sai com `X-Frame-Options`, `X-Content-Type-Options` ou `Strict-Transport-Security`, e não existe `CORSMiddleware` com allowlist.

**Como explorar:** qualquer resposta da API confirma a ausência.

```bash
curl -s -D - -o /dev/null http://127.0.0.1:8000/health
```

Os headers de resposta não incluem nenhum dos três citados.

**Por que é grave aqui:** a página `/recepcao/agenda`, que mostra dado de paciente em HTML, pode ser embutida em um `<iframe>` de um site malicioso (clickjacking), já que falta `X-Frame-Options`.


Estes três findings correspondem às ameaças T-07, T-01 e T-22 do threat model (`04_threat_model.md`).
