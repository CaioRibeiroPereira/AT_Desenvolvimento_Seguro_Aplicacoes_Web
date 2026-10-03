# Exercício 13: Auditoria final e relatório de rastreabilidade

Escopo: API de Agendamento Clínico (FastAPI), auditada antes do primeiro deploy.

Referências: threat model do Ex4 (`docs/04_threat_model.md`, IDs T-xx e MC-xx), relatório ZAP em `zap_baseline_report.html`/`.md`, testes em `tests/`.

## 1. Resumo da auditoria

| Verificação                         | Ferramenta                 | Resultado                                                                                                                                                |
| ----------------------------------- | -------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Scan passivo (baseline)             | OWASP ZAP 2.17.0           | 0 High, 2 Medium, 5 Low, 2 Informational (console: 0 FAIL, 7 WARN, 60 PASS)                                                                                                                                  |
| Testes automatizados                | pytest (48 passed)         | 8 com mock em `test_ex13_unitarios_mock.py`, 4 de auditoria em `test_ex13_auditoria.py`, 6 novos de escrita e forja de token em `test_ex12_seguranca.py` |
| Auditoria da especificação OpenAPI  | leitura de `/openapi.json` | 5 achados (seção 4)                                                                                                                                      |
| Correlação threat model x evidência | análise manual             | 19 existentes, 3 parciais, 0 previstas (seção 3)                                                                                                         |

Correções feitas nesta etapa, com base nos problemas encontrados na versão anterior deste relatório:

* **Trilha de auditoria (T-11):** foi criada a tabela `auditlog`, que é gravada na mesma transação usada para criar, alterar e apagar uma consulta. A consulta dos registros é feita por `GET /admin/auditoria`.

* **MFA por usuário (T-02):** foi usado TOTP (RFC 6238), com um segredo diferente para cada conta de administrador, gerado no seed. Isso substitui o código fixo que ficava no `.env`.

* **`/docs` e `/openapi.json`:** são desativados quando `ENVIRONMENT=production`. Foi verificado que ficam com status 200 em desenvolvimento e 404 em produção.

O scan ZAP foi executado novamente na versão final (`zap_final_report.html` e `.md`) e teve o mesmo resultado do scan anterior: 0 High, 2 Medium, 5 Low e 2 Informational. O HTML difere do baseline apenas na data de geração; o Markdown é idêntico porque o resultado é o mesmo. Esse scan ainda foi executado em modo de desenvolvimento, por isso os alertas relacionados a `/docs` continuam aparecendo.

## 2. Findings do ZAP correlacionados

O scan foi feito usando o baseline, com spider limitado a `/docs` e regras passivas. Nenhum alerta teve severidade alta.

| Alerta ZAP                                                         | ID                | Categoria OWASP                               | Local                                       | Análise                                                                                                                                                                                                         | Ação                                                                |
| ------------------------------------------------------------------ | ----------------- | --------------------------------------------- | ------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------- |
| Content Security Policy (CSP) Header Not Set                       | 10038             | A05:2021 Security Misconfiguration            | `/docs`                                     | Não há CSP. A página HTML da recepção (T-19/T-20) usa o auto-escape do Jinja2 como principal proteção; a CSP seria uma proteção extra.                                                                          | Residual, recomendado antes do deploy                               |
| Permissions Policy Header Not Set                                  | 10063             | A05:2021                                      | `/docs`                                     | É um cabeçalho de proteção extra, sem impacto direto nos dados e recursos da aplicação.                                                                                                                         | Residual, baixo                                                     |
| Cross-Origin-Embedder/Opener/Resource-Policy ausentes ou inválidos | 90004 (3 alertas) | A05:2021                                      | `/docs`                                     | Mesmo caso do alerta anterior; esses cabeçalhos ajudam no isolamento entre origens.                                                                                                                             | Residual, baixo                                                     |
| Cross-Domain JavaScript Source File Inclusion                      | 10017             | A08:2021 Software and Data Integrity Failures | `/docs`                                     | O Swagger UI carrega JavaScript de uma CDN externa. Isso só acontece porque `/docs` está disponível.                                                                                                            | Ver achado O-03                                                     |
| Sub Resource Integrity Attribute Missing                           | 90003 (2 alertas) | A08:2021                                      | `/docs`                                     | Os scripts da CDN não possuem `integrity`. A causa é a mesma do alerta anterior.                                                                                                                                | Ver achado O-03                                                     |
| Storable and Cacheable Content                                     | 10049             | A05:2021                                      | `/docs`, `/`, `/robots.txt`, `/sitemap.xml` | Nenhuma resposta da aplicação define `Cache-Control`. Como as respostas de `/consultas` são JSON e não possuem `Last-Modified`, o risco prático de cache intermediário é baixo, mas os dados são de saúde (A1). | Residual, recomendado: `Cache-Control: no-store` nas rotas clínicas |
| Modern Web Application                                             | 10109             | Informativo                                   | `/docs`                                     | Apenas identifica o framework JavaScript; não é uma vulnerabilidade.                                                                                                                                            | Sem ação                                                            |

Os alertas de `/`, `/robots.txt` e `/sitemap.xml` são 404 esperados, pois a API não possui essas rotas, e não representam um finding.

## 3. Rastreabilidade threat model → código → evidência

Para cada ameaça do Ex4, são mostrados a proteção aplicada, onde ela está no código e como ela foi verificada.

| ID   | Categoria OWASP (API 2023 ou Top 10 2021)            | Mitigação no código                                                                                                                  | Evidência                                                          | Status                         |
| ---- | ---------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------ | ------------------------------ |
| T-01 | API2:2023 Broken Authentication                      | `@limiter.limit("5/minute")` em `app/routes/auth.py`                                                                                 | tests/test_ex10_hardening.py::test_rate_limit_diferenciado_no_login | Existente                      |
| T-02 | API2:2023                                            | TOTP por usuário admin (`pyotp`, segredo em `user.mfa_secret`, gerado no seed) em `app/routes/auth.py`                               | `tests/test_autorizacao.py` (login admin exige MFA)                | Existente, com ressalva (R-02) |
| T-03 | A02:2021 Cryptographic Failures                      | bcrypt em `app/auth/security.py` (hash com `DUMMY_HASH` para manter tempo constante)                                                 | tests/test_autorizacao.py (login e hash não exposto) | Existente                      |
| T-04 | API2:2023                                            | Assinatura e expiração do JWT em `app/auth/`                                                                                         | tests/test_ex12_seguranca.py (JWT adulterado, expirado e forjado) | Existente                      |
| T-05 | API2:2023                                            | Mensagem de erro genérica no login                                                                                                   | tests/test_autorizacao.py::test_login_com_senha_errada_ou_usuario_inexistente_da_mesma_resposta | Existente                      |
| T-06 | API3:2023 Broken Object Property Level Authorization | `response_model=ConsultaRead`                                                                                                        | tests/test_exposicao_e_xss.py::test_response_model_nao_expoe_campos_internos_de_auditoria | Existente                      |
| T-07 | API1:2023 Broken Object Level Authorization          | `app/auth/ownership.py` (verificação centralizada)                                                                                   | tests/test_ex9_correcoes.py (test_bola_corrigida_*) | Existente                      |
| T-08 | API3:2023                                            | `extra="forbid"` em `ConsultaCreate` e `ConsultaUpdate` (confirmado no OpenAPI: `additionalProperties: false`)                       | `tests/test_ex12_seguranca.py`                                     | Existente                      |
| T-09 | A03:2021 Injection                                   | Pydantic: tipo, `maxLength` 280, `minLength` 3, `pattern` em `motivo`                                                                | `tests/test_ex9_correcoes.py`, `tests/test_ex13_unitarios_mock.py` | Existente                      |
| T-10 | API1:2023                                            | Ownership e RBAC nas rotas de escrita                                                                                                | `tests/test_autorizacao.py`                                        | Existente                      |
| T-11 | A09:2021 Logging and Monitoring Failures             | Tabela `auditlog` (`app/models/auditoria.py`), gravada por `app/auditoria.py` na mesma transação de criar, alterar e apagar consulta | `tests/test_ex13_auditoria.py`                                     | Existente                      |
| T-12 | API4:2023 Unrestricted Resource Consumption          | `100/minute` por IP (global); sem limite de tamanho de payload                                                                       | n/a                                                                | Parcial                        |
| T-13 | API5:2023 Broken Function Level Authorization        | RBAC com três papéis, verificação em `app/auth/deps.py`                                                                              | `tests/test_ex13_unitarios_mock.py`                                | Existente                      |
| T-14 | API1:2023                                            | Ownership impede leitura, mas 403 e 404 podem ser diferenciados                                                                      | `tests/test_ex12_seguranca.py`                                     | Parcial (R-01)                 |
| T-15 | API2:2023                                            | Client Credentials com token de vida curta                                                                                           | `tests/test_m2m.py`                                                | Existente                      |
| T-16 | API5:2023                                            | Escopo `slots:read` e claim que diferencia M2M de profissional                                                                       | `tests/test_m2m.py`                                                | Existente                      |
| T-17 | API3:2023                                            | `/slots` retorna somente horários ocupados, sem dados de paciente                                                                                             | `tests/test_m2m.py`                                                | Existente                      |
| T-18 | API4:2023                                            | Rate limit por IP, não por cliente M2M                                                                                               | n/a                                                                | Parcial                        |
| T-19 | A03:2021 Injection (XSS)                             | `autoescape=True` no Jinja2                                                                                                          | `tests/test_exposicao_e_xss.py`                                    | Existente                      |
| T-20 | A03:2021                                             | Auto-escape e `X-Frame-Options`                                                                                                      | `tests/test_exposicao_e_xss.py`                                    | Existente                      |
| T-21 | A01:2021 Broken Access Control                       | Autenticação e papel de recepção na rota `/recepcao/agenda`                                                                          | tests/test_ex9_correcoes.py::test_agenda_exige_autenticacao | Existente                      |
| T-22 | A05:2021                                             | `X-Frame-Options: DENY` em `app/main.py`                                                                                             | tests/test_ex10_hardening.py::test_headers_de_seguranca_presentes_em_toda_resposta | Existente                      |

Contagem: 19 existentes, 3 parciais (T-12, T-14, T-18), 0 previstas.

Os cabeçalhos `X-Content-Type-Options`, `Strict-Transport-Security` e `X-Frame-Options` estão em `app/main.py`. O CORS usa uma lista de origens permitidas, sem usar `*`.

## 4. Auditoria da especificação OpenAPI

Rotas auditadas: 12 operações em 8 caminhos, verificadas em `/openapi.json`.

| ID   | Achado                                                                                                                 | Severidade | Análise                                                                                                                                                                                                    |
| ---- | ---------------------------------------------------------------------------------------------------------------------- | ---------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| O-01 | Operações protegidas não documentam 401, 403 nem 404. Só aparecem 200, 201, 204 e 422.                                 | Baixa      | A especificação não mostra a diferença entre 403 e 404 que T-14 descreve. Quem integra a API não sabe que deve tratar 401/403.                                                                             |
| O-02 | Login usa o fluxo OAuth2 **password** (`tokenUrl: /auth/login`) com `username`, `password` e `mfa_code` no formulário. | Média      | O fluxo **password** é desencorajado no OAuth 2.1, porque o cliente recebe e manipula a senha. Foi aceito porque o cliente é a própria clínica, mas continua sendo um risco de design.                     |
| O-03 | `/docs` e `/openapi.json` estavam públicos (S5 do threat model).                                                       | Média      | Isso expõe toda a estrutura da API. Foi corrigido: as rotas são desativadas com `ENVIRONMENT=production`. Em desenvolvimento continuam ativas, e os alertas 10017 e 90003 do ZAP só se aplicam nesse modo. |
| O-04 | `password` (login) e `username` não têm `maxLength`.                                                                   | Baixa      | Senhas muito longas podem consumir CPU no bcrypt (que limita a senha a 72 bytes). É uma parte ainda não resolvida de T-12.                                                                                 |
| O-05 | `client_secret` do login está marcado como `format: password`, mas o campo existe no formulário de usuário.            | Baixa      | O campo não tem uso legítimo nessa rota. Ele deveria ser removido do schema de login.                                                                                                                      |

Pontos positivos confirmados na spec: `additionalProperties: false` em `ConsultaCreate` e `ConsultaUpdate`; `maxLength` e `pattern` em `motivo`; esquemas `ClienteM2M` separados de `UsuarioLogin`; `/health` é a única rota pública sem dados.

## 5. Riscos residuais

| ID   | Risco                                                                                                                    | Relacionado a               | Impacto                                                                      | Decisão                                                                                                                             |
| ---- | ------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ---------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| R-01 | 403 e 404 podem ser diferenciados, permitindo descobrir quais IDs existem                                                | T-14                        | Baixo a médio (dado de paciente, mas sem conteúdo exposto)                   | **Aceitável** para deploy. Corrigir retornando 404 para IDs de outros usuários.                                                     |
| R-02 | TOTP não possui proteção contra replay dentro da janela de 30 s (`valid_window=1`, aceita o código anterior ou seguinte) | T-02                        | Baixo: é necessário interceptar o código e usá-lo em até 1 min               | **Aceitável**. Melhoria: registrar o último código usado por conta.                                                                 |
| R-03 | Segredo TOTP fica armazenado em texto claro no banco (necessário para gerar o código)                                    | T-02, T-03                  | Médio: quem tiver acesso ao banco pode gerar códigos válidos                 | **Aceitável** com controle de acesso ao arquivo do banco. Melhoria: criptografar o campo usando uma chave armazenada fora do banco. |
| R-04 | Segredo TOTP do admin aparece no console na primeira inicialização                                                       | T-02                        | Baixo: acontece apenas na primeira execução                                  | **Aceitável**. Quem cadastrou o autenticador deve limpar o log.                                                                     |
| R-05 | Limite de requisições por IP, sem limite por cliente M2M nem limite de payload                                           | T-12, T-18                  | Médio: pode haver flood usando vários IPs ou um token de laboratório         | **Aceitável** com monitoramento.                                                                                                    |
| R-06 | Falta de CSP e de cabeçalhos de isolamento de origem                                                                     | alertas 10038, 90004, 10063 | Baixo a médio: são proteções extras para a página da recepção                | **Aceitável** para deploy, com CSP como melhoria.                                                                                   |
| R-07 | Falta de `Cache-Control` nas rotas clínicas                                                                              | alerta 10049                | Baixo: sem `Last-Modified`, o risco de cache intermediário é pequeno         | **Aceitável**, com `no-store` recomendado.                                                                                          |
| R-08 | Login por IP (5/min) sem limite por conta                                                                                | T-01                        | Médio: um atacante usando vários IPs ainda pode tentar acessar a mesma conta | **Aceitável** com bloqueio temporário por conta como melhoria.                                                                      |

## 6. Decisão de liberação

**Autorizar o deploy, com uma condição:**

1. Definir `ENVIRONMENT=production` no ambiente de produção. Sem isso, `/docs` continuará público.

Os três problemas da versão anterior foram resolvidos (trilha de auditoria, TOTP por usuário e possibilidade de desativar `/docs`). Os riscos R-01 e R-02 a R-08 são considerados aceitáveis e ficam registrados como dívida técnica.

Nenhum finding do ZAP possui severidade alta.

## 7. Limitações desta auditoria

* O scan ZAP foi feito usando o baseline passivo, com spider limitado a `/docs` (a raiz `/` retorna 404). Para testar todas as rotas, seria necessário usar `zap-api-scan` com o `openapi.json`.

* O scan não executa ataques ativos, como SQLi, IDOR e fuzzing. Esses casos estão cobertos pelos testes pytest de autorização e entrada, e não pelo ZAP.

* Os testes com mock verificam a lógica de autorização e validação de forma isolada. Eles não substituem testes de integração usando um banco de dados real.
