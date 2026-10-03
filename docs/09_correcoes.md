# Exercício 9: Correção de vulnerabilidades de entrada e saída

Corrige os três findings do Ex8 (`08_owasp_findings.md`), de forma centralizada, e aplica a mesma correção de controle de acesso a um endpoint que não foi citado lá.

## 1. BOLA (Finding 1): ownership também na leitura

Antes, `GET /consultas/{id}` e `GET /consultas` só exigiam login (`get_current_user`), sem checar o dono do registro. Agora usam `verificar_ownership_leitura` e `query_visiveis`, centralizados em `app/auth/ownership.py` (o mesmo módulo que já fazia a checagem de escrita desde o Ex6, então a lógica de segurança continua em um único lugar).

Regra: `admin` e `recepcionista` continuam vendo qualquer consulta (função deles no negócio); `profissional` só vê as suas.

**Antes/depois (mesmo ataque do Ex8):**

```
dr_souza GET /consultas/1 (consulta de paciente de dr_silva)
antes: 200, corpo com o motivo completo
depois: 403
```

Confirmado em `tests/test_ex9_correcoes.py::test_bola_corrigida_profissional_nao_le_consulta_de_outro`.

## 2. Validação whitelist e regex, e `extra='forbid'`

`app/schemas/consulta.py` ganhou:

- `model_config = ConfigDict(extra="forbid")` em `ConsultaCreate` e `ConsultaUpdate`: qualquer campo não declarado no payload (ex.: tentar mandar `created_by`) é rejeitado com 422, em vez de ser silenciosamente ignorado.
- `pattern` (regex) no campo `motivo`, restringindo a um conjunto whitelisted de caracteres (letras, números, pontuação básica). Isso bloqueia `<` e `>` na entrada, então um payload como `<script>...</script>` nem chega a ser salvo.

**Antes/depois (mesmo ataque do Ex8, variante de entrada):**

```
POST /consultas com motivo = "<script>alert(1)</script>"
antes: 201, consulta criada normalmente
depois: 422, rejeitado na validação
```

Confirmado em `test_motivo_com_tag_html_e_rejeitado_na_entrada` e `test_extra_forbid_rejeita_campo_nao_declarado`.

## 3. Output encoding (Jinja2) continua como segunda camada

A validação de entrada bloqueia `<script>` vindo da API, mas não cobre dado que chegue ao armazenamento por outro caminho (ex.: migração futura). Por isso o auto-escape do Jinja2, já ligado desde o Ex2, continua ativo e foi testado separadamente: um registro inserido direto no armazenamento (sem passar pela validação da API) ainda sai escapado na página da recepção. Teste: `test_agenda_html_escapa_payload_xss_ja_armazenado`.

## 4. Middleware JWT centralizado

Já existia desde o Ex6 (`app/auth/deps.py`: `get_current_user`, `require_roles`, `get_current_client`, `require_scope`). Nenhuma rota reimplementa verificação de token; todas dependem desse módulo único.

## 5. Endpoint não citado no Ex8: `GET /recepcao/agenda`

Essa rota não tinha nenhuma autenticação, qualquer pessoa, sem token, via o `motivo` de todas as consultas do dia. É o mesmo padrão de controle de acesso quebrado do Finding 1, só que mais grave (falta autenticação inteira, não só ownership). Corrigido com a mesma dependência central (`require_roles`), liberando só `recepcionista` e `admin`.

**Antes/depois:**

```
GET /recepcao/agenda (sem token)
antes: 200, HTML com dado de paciente
depois: 401
```

Confirmado em `test_agenda_exige_autenticacao` e `test_agenda_bloqueia_profissional_e_libera_recepcao`.

## 6. Testes

`tests/test_ex9_correcoes.py` (novo) cobre os pontos 1, 2 e 5. `tests/test_exposicao_e_xss.py` foi ajustado para provar o ponto 3. Suíte completa: 23 testes passando.

**Evidências:**

1. **BOLA corrigida:** loguei como dr_silva e criei uma consulta em `POST /consultas`. Entrei depois como dr_souza e usei o id 1 da consulta criada anteriormente. Resultado: erro 403 (acesso negado), como esperado.
2. **extra='forbid':** loguei novamente como dr_silva e enviei um campo extra na requisição.
3. **Regex bloqueando XSS.**
4. **Acesso à agenda sem token.**

# Exercício 10: Hardening de rede e proteção contra abuso

## 1. CORS com lista de origens permitidas

O `CORSMiddleware`, configurado em `app/main.py`, usa a lista `ALLOWED_ORIGINS` do `.env`, com as origens separadas por vírgula. Exemplo: `http://localhost:3000,http://127.0.0.1:3000`. O uso de `"*"` não é permitido. Origens fora da lista não recebem o cabeçalho `Access-Control-Allow-Origin`, impedindo o navegador de acessar a resposta.

## 2. Cabeçalhos de segurança

O middleware `security_headers`, em `app/main.py`, adiciona três cabeçalhos a todas as respostas:

- `X-Frame-Options: DENY`: impede que páginas da API sejam exibidas em iframe, ajudando a evitar ataques de clickjacking.
- `X-Content-Type-Options: nosniff`: impede que o navegador interprete arquivos com um tipo diferente do informado.
- `Strict-Transport-Security: max-age=31536000; includeSubDomains`: força o uso de HTTPS em produção.

## 3. Limite de tentativas de login

O arquivo `app/rate_limit.py` configura o `Limiter` do SlowAPI com um limite geral de 100 requisições por minuto, por IP. Esse controle é registrado uma única vez em `app/main.py`.

A rota `POST /auth/login` tem um limite específico de 5 tentativas por minuto, definido por `@limiter.limit("5/minute")`, para dificultar ataques de força bruta (ameaça T-01).

## 4. Antes e depois

| Controle | Antes (Ex8) | Depois |
|---|---|---|
| CORS | Sem configuração | Lista de origens permitidas |
| Cabeçalhos | Ausentes | Três cabeçalhos de segurança em todas as respostas |
| Login | Tentativas ilimitadas | A 6ª tentativa no mesmo minuto recebe erro 429 Too Many Requests |

## 5. Testes

O arquivo `tests/test_ex10_hardening.py` verifica os cabeçalhos de segurança, a rejeição de origens não permitidas, a liberação de origens autorizadas e o bloqueio da 6ª tentativa de login no mesmo minuto.

Nos demais testes, o limitador fica desativado em `tests/conftest.py`, pois eles realizam vários logins e não têm como objetivo testar esse controle.

## 6. Limitação conhecida

O limite de 100 requisições por minuto é aplicado por IP, e não por usuário autenticado. Isso ajuda a combater excesso de requisições (T-12) e abusos vindos do laboratório (T-18), mas não diferencia clientes que compartilham o mesmo IP, como em um proxy corporativo. Por isso, esse controle é classificado como parcial no modelo de ameaças.

**EVIDÊNCIAS**
