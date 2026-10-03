# Exercício 9: Correção de vulnerabilidades de entrada e saída

Corrige os três findings do Ex8 (`08_owasp_findings.md`), de forma centralizada, e aplica a mesma correção de controle de acesso a um endpoint que não foi citado lá.

## 1. BOLA (Finding 1): ownership também na leitura

Antes, `GET /consultas/{id}` e `GET /consultas` só exigiam login (`get_current_user`), sem checar o dono do registro. Agora usam `verificar_ownership_leitura` e `filtrar_visiveis`, centralizados em `app/auth/ownership.py` (o mesmo módulo que já fazia a checagem de escrita desde o Ex6, então a lógica de segurança continua em um único lugar).

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
depois: 422, rejeitado na validacao
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

## 6. O que fica para o Ex10

Os Findings 2 (sem rate limiting no login) e 3 (sem cabeçalhos de segurança) do Ex8 não são corrigidos aqui, porque pertencem ao escopo do Ex10 (hardening de rede). Prevenção de SQL injection também não se aplica ainda: a persistência continua em memória até o Ex11, então não existe consulta SQL no código hoje.

## 7. Testes

`tests/test_ex9_correcoes.py` (novo) cobre os pontos 1, 2 e 5. `tests/test_exposicao_e_xss.py` foi ajustado para provar o ponto 3. Suíte completa: 23 testes passando.
