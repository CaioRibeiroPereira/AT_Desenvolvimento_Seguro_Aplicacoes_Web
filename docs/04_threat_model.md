# Exercício 4: Threat Model (STRIDE)

Modelo de ameaças da API de agendamento clínico. Cada ameaça tem um ID (T-xx) e cada misuse case tem um ID (MC-xx), para que a correção de vulnerabilidades, os testes de segurança e o relatório final possam citá-los diretamente. O status da mitigação é "Existente" (já no código) ou "Prevista" (ainda não implementada).

## 1. Ativos

| ID | Ativo | Por que importa |
|---|---|---|
| A1 | Dados de paciente (`paciente_id`, `motivo` da consulta) | Dado de saúde, sensível pela LGPD |
| A2 | Agenda de consultas (data, profissional, status) | Integridade da operação da clínica |
| A3 | Credenciais e hashes de senha | Comprometimento dá acesso a todos os outros ativos |
| A4 | Tokens (JWT de usuário e token M2M do laboratório) | Quem tem o token age como o dono dele |
| A5 | Campos internos de auditoria (`created_by`, `internal_notes`) | Facilitam identificar usuários e rastrear ações |
| A6 | Disponibilidade da API | Recepção e profissionais dependem dela no dia a dia |

## 2. Superfícies de ataque

| ID | Superfície | Cliente |
|---|---|---|
| S1 | `POST/GET/PUT/PATCH/DELETE /consultas` e `/consultas/{id}` | Frontend JSON |
| S2 | `GET /recepcao/agenda?data=` (HTML renderizado) | Navegador da recepção |
| S3 | Endpoint de login (recebe usuário, senha e código MFA) | Todos os usuários |
| S4 | Endpoint de horários disponíveis (`/slots`) | Laboratório parceiro (M2M) |
| S5 | Documentação automática (`/docs`, `/openapi.json`) | Qualquer cliente |
| S6 | Corpo JSON das requisições (campos aceitos e ignorados) | Frontend JSON |

## 3. Misuse cases

| ID | Misuse case | Atacante | Superfície |
|---|---|---|---|
| MC-01 | Paciente autenticado troca o id na URL e lê a consulta de outro paciente | Usuário legítimo mal-intencionado | S1 |
| MC-02 | Atacante grava `<script>` no campo `motivo` para executar código no navegador de quem abrir a agenda | Usuário com acesso de escrita | S1, S2 |
| MC-03 | Força bruta de senhas no login até acertar a conta de um administrador | Externo anônimo | S3 |
| MC-04 | Token do laboratório vazado é usado para ler ou alterar consultas clínicas | Externo com token roubado | S4, S1 |
| MC-05 | Recepcionista ou profissional tenta acessar rota de administrador | Usuário interno | S1 |
| MC-06 | Cliente envia campos extras (`created_by`, `internal_notes`, `id`) para sobrescrever dados internos | Usuário legítimo mal-intencionado | S6 |
| MC-07 | JWT é adulterado (papel trocado para admin, expiração alterada) ou reaproveitado depois de expirado | Externo ou interno | S1, S3 |
| MC-08 | Enumeração de ids sequenciais (1, 2, 3...) para varrer todas as consultas | Externo ou interno | S1 |
| MC-09 | Flood de requisições derruba ou degrada a API | Externo anônimo | S1, S3, S4 |
| MC-10 | Usuário altera ou apaga uma consulta e depois nega ter feito, sem que haja registro | Usuário interno | S1 |

## 4. STRIDE por componente

Legenda: S = Spoofing, T = Tampering, R = Repudiation, I = Information disclosure, D = Denial of service, E = Elevation of privilege.

### 4.1 Componente: endpoint de login (S3)

| ID | STRIDE | Ameaça | Misuse case | Mitigação | Status |
|---|---|---|---|---|---|
| T-01 | S | Adivinhar senha por força bruta e se passar por outro usuário | MC-03 | Rate limiting diferenciado no login | Existente |
| T-02 | S | Roubo de senha vazada permite acesso à conta admin | MC-03 | MFA para contas administrativas | Existente |
| T-03 | I | Senhas em texto plano expostas se o armazenamento vazar | MC-03 | Hash bcrypt, nunca texto plano | Existente |
| T-04 | T | JWT adulterado ou sem expiração vira sessão eterna | MC-07 | Assinatura do JWT verificada e expiração obrigatória | Existente |
| T-05 | I | Mensagem de erro diferente para "usuário não existe" e "senha errada" permite descobrir usuários válidos | MC-03 | Mensagem de erro genérica única | Existente |

### 4.2 Componente: endpoint de consultas (S1, S6)

| ID | STRIDE | Ameaça | Misuse case | Mitigação | Status |
|---|---|---|---|---|---|
| T-06 | I | Resposta expõe campos internos de auditoria | MC-06 | `response_model=ConsultaRead` com whitelist de campos | Existente |
| T-07 | I | BOLA: usuário lê consulta de outro paciente trocando o id | MC-01, MC-08 | Verificação de ownership centralizada em cada acesso por id | Existente |
| T-08 | T | Mass assignment: campos extras no corpo sobrescrevem dados internos | MC-06 | `extra="forbid"` nos schemas de entrada | Existente |
| T-09 | T | Entrada malformada ou fora do esperado corrompe dados | MC-02 | Validação de tipo, `Enum` e limite de tamanho via Pydantic | Existente |
| T-10 | T | `PUT`/`PATCH`/`DELETE` em consulta de outro usuário | MC-01 | Ownership e RBAC nas rotas de escrita | Existente |
| T-11 | R | Alteração ou exclusão sem registro de quem fez | MC-10 | Campo `created_by` preenchido com o usuário autenticado e log de auditoria | Prevista |
| T-12 | D | Excesso de requisições esgota a API | MC-09 | Rate limiting e limites de tamanho de payload | Parcial |
| T-13 | E | Papel comum acessa rota de administrador | MC-05 | RBAC com três papéis e checagem centralizada | Existente |
| T-14 | I | Ids sequenciais facilitam varredura | MC-08 | Ownership impede leitura mesmo com id válido; respostas 404 uniformes | Existente |

### 4.3 Componente: integração M2M do laboratório (S4)

| ID | STRIDE | Ameaça | Misuse case | Mitigação | Status |
|---|---|---|---|---|---|
| T-15 | S | Alguém se passa pelo laboratório com token roubado | MC-04 | Client Credentials com token de vida curta e segredo do cliente fora do código | Existente |
| T-16 | E | Token do laboratório usado em rota clínica | MC-04 | Escopo mínimo (`slots:read`) e claim que distingue token M2M de token de profissional | Existente |
| T-17 | I | Laboratório recebe mais dados do que precisa | MC-04 | Resposta de `/slots` só com horários livres, sem dados de paciente | Existente |
| T-18 | D | Laboratório (ou quem tem seu token) sobrecarrega a API | MC-09 | Rate limiting por cliente | Parcial |

### 4.4 Componente: página HTML da recepção (S2)

| ID | STRIDE | Ameaça | Misuse case | Mitigação | Status |
|---|---|---|---|---|---|
| T-19 | T | XSS stored: `<script>` em `motivo` executa no navegador da recepção | MC-02 | Auto-escape do Jinja2 (`autoescape=True` explícito) | Existente |
| T-20 | I | XSS roubaria sessão e dados de pacientes exibidos na página | MC-02 | Auto-escape do Jinja2; cabeçalhos de segurança | Existente |
| T-21 | I | Página da agenda acessível sem autenticação | MC-01 | Exigir autenticação e papel de recepção na rota | Existente |
| T-22 | T | Clickjacking: página embutida em iframe de site malicioso | MC-02 | `X-Frame-Options` | Existente |

## 5. Threat model consolidado

| ID | Ameaça (resumo) | STRIDE | Ativo | Superfície | Categoria OWASP | Mitigação | Status |
|---|---|---|---|---|---|---|---|
| T-01 | Força bruta no login | S | A3 | S3 | API2:2023 Broken Authentication | Rate limiting no login | Existente |
| T-02 | Conta admin comprometida | S | A3 | S3 | API2:2023 | MFA admin | Existente |
| T-03 | Senha em texto plano | I | A3 | S3 | A02:2021 Cryptographic Failures | Hash bcrypt | Existente |
| T-04 | JWT adulterado ou eterno | T | A4 | S3 | API2:2023 | Assinatura e expiração | Existente |
| T-05 | Enumeração de usuários | I | A3 | S3 | API2:2023 | Erro genérico | Existente |
| T-06 | Vazamento de campos internos | I | A5 | S1 | API3:2023 Broken Object Property Level Authorization | `response_model` | Existente |
| T-07 | BOLA em leitura | I | A1 | S1 | API1:2023 Broken Object Level Authorization | Ownership centralizado | Existente |
| T-08 | Mass assignment | T | A2, A5 | S6 | API3:2023 | `extra="forbid"` | Existente |
| T-09 | Entrada inválida | T | A2 | S1 | A03:2021 Injection | Validação Pydantic | Existente |
| T-10 | Escrita em consulta alheia | T | A2 | S1 | API1:2023 | Ownership e RBAC | Existente |
| T-11 | Repúdio de ações | R | A2 | S1 | A09:2021 Logging and Monitoring Failures | Auditoria com usuário autenticado | Prevista |
| T-12 | Flood na API | D | A6 | S1 | API4:2023 Unrestricted Resource Consumption | Rate limiting | Parcial |
| T-13 | Escalada de privilégio | E | A1, A2 | S1 | API5:2023 Broken Function Level Authorization | RBAC | Existente |
| T-14 | Varredura por ids | I | A1 | S1 | API1:2023 | Ownership e 404 uniforme | Existente |
| T-15 | Falsificação do laboratório | S | A4 | S4 | API2:2023 | Client Credentials | Existente |
| T-16 | Token M2M em rota clínica | E | A1, A2 | S4, S1 | API5:2023 | Escopo e claims | Existente |
| T-17 | Excesso de dados ao laboratório | I | A1 | S4 | API3:2023 | Resposta mínima em `/slots` | Existente |
| T-18 | Abuso via token M2M | D | A6 | S4 | API4:2023 | Rate limiting por cliente | Parcial |
| T-19 | XSS stored | T | A1 | S2 | A03:2021 Injection | Auto-escape Jinja2 | Existente |
| T-20 | Roubo de sessão via XSS | I | A1, A4 | S2 | A03:2021 | Auto-escape e cabeçalhos | Existente |
| T-21 | Agenda sem autenticação | I | A1 | S2 | A01:2021 Broken Access Control | Autenticação na rota | Existente |
| T-22 | Clickjacking | T | A1 | S2 | A05:2021 Security Misconfiguration | `X-Frame-Options` | Existente |

## 6. Resumo do estado atual

- **Existentes (20):** T-01 a T-10, T-13 a T-17, T-19 a T-22. Cobrem autenticação (MFA, hash, JWT, rate limiting no login), autorização (BOLA, RBAC, ownership), entrada validada, escopos M2M, XSS stored, CORS e cabeçalhos de segurança.
- **Parciais (2):** T-12 e T-18. Existe rate limiting geral (100/minuto por IP), mas falta limite de tamanho de payload (T-12) e um limite específico por cliente M2M, não só por IP (T-18).
- **Prevista (1):** T-11 (trilha de auditoria de alterações). Fora do escopo dos exercícios até aqui; fica para uma eventual revisão futura.
- **Maior risco em aberto:** T-11, já que nenhuma alteração ou exclusão de consulta fica registrada com rastro de quem fez.
