# Exercício 5: Arquitetura de segurança e vetores de ataque

Complementa o threat model (`04_threat_model.md`) com as partições do sistema, as fronteiras de segurança e os vetores de ataque nos três eixos de segurança de APIs. Os IDs T-xx referem-se ao threat model.

## 1. Partições do sistema

| ID | Partição | Responsabilidade |
|---|---|---|
| P1 | Clientes externos | Frontend JSON, navegador da recepção, laboratório (M2M) |
| P2 | Borda HTTP | Entrada das requisições. Ponto único de CORS, cabeçalhos e rate limiting (`app/main.py`) |
| P3 | Rotas | Endpoints `/consultas` e `/recepcao/agenda` (`app/routes/`) |
| P4 | Validação e contratos | Schemas Pydantic de entrada e saída (`app/schemas/`) |
| P5 | Segurança | Autenticação, autorização e ownership (`app/auth/`, prevista) |
| P6 | Apresentação | Templates Jinja2 com auto-escape (`app/templates/`) |
| P7 | Dados | Modelos e armazenamento (`app/models/`, `app/database/`) |
| P8 | Segredos | Variáveis de ambiente e credenciais (`.env`, previsto) |
| P9 | Cadeia de build | Dependências e pipeline (`requirements.txt`, CI) |

## 2. Diagrama e fronteiras

```mermaid
flowchart TB
    subgraph b1["Fora do sistema (nao confiavel)"]
        P1["P1 Clientes: frontend JSON, recepcao, laboratorio M2M"]
    end

    subgraph borda["Fronteira B1: borda HTTP"]
        P2["P2 Borda HTTP: CORS, headers, rate limiting"]
    end

    subgraph app["Aplicacao FastAPI"]
        P3["P3 Rotas: /consultas, /recepcao/agenda"]
        P4["P4 Validacao e contratos: schemas Pydantic"]
        P5["P5 Seguranca: autenticacao, autorizacao, ownership (prevista)"]
        P6["P6 Apresentacao: Jinja2 com auto-escape"]
    end

    subgraph dados["Fronteira B2: dados"]
        P7[("P7 Dados: modelos e armazenamento")]
    end

    subgraph b3["Fronteira B3: configuracao e cadeia de build"]
        P8["P8 Segredos e .env (previsto)"]
        P9["P9 Dependencias e pipeline"]
    end

    P1 -- "F1 F2 F3 requisicao" --> P2
    P2 --> P3
    P3 -- "F4 valida entrada" --> P4
    P3 -- "F5 decide acesso" --> P5
    P3 -- "F6 leitura e escrita" --> P7
    P3 -- "F8 renderiza" --> P6
    P2 -- "F9 resposta filtrada ou HTML escapado" --> P1
    P8 -- "F10 segredos" --> P2
    P8 -- "F10 conexao" --> P7
    P9 -- "codigo e bibliotecas" --> P2
```

- **B1, Internet para borda HTTP:** todo dado que entra é não confiável.
- **B2, aplicação para dados:** só as rotas, depois de validar e autorizar, acessam os dados.
- **B3, código e dependências para produção:** dependência comprometida ou segredo vazado entram por aqui, sem passar por B1.

## 3. Fluxo de dados

- **F1 a F3 (B1):** frontend, recepção e laboratório enviam requisições à borda. Carregam dado de paciente e tokens.
- **F4 e F5:** as rotas enviam o corpo da requisição para validação (P4) e o token para decisão de acesso (P5).
- **F6 (B2):** as rotas leem e gravam consultas em P7.
- **F7 e F8:** o objeto interno sai filtrado por `ConsultaRead` (JSON) ou escapado pelo Jinja2 (HTML).
- **F9 (B1):** resposta volta ao cliente, sem campos internos.
- **F10 (B3):** segredos e string de conexão chegam à borda e aos dados.

Os fluxos com dado sensível são F1, F6, F7, F8 e F9.

## 4. Vetores de ataque por eixo

### Eixo 1: Design

| ID | Vetor | Ameaça |
|---|---|---|
| V-01 | Sem modelo de autorização definido: qualquer cliente alcança qualquer recurso | T-13, T-21 |
| V-02 | Ids sequenciais em `/consultas/{id}` facilitam varredura | T-14 |
| V-03 | Laboratório sem privilégio mínimo, com acesso parecido ao de usuários internos | T-16, T-17 |
| V-04 | Sem trilha de auditoria de quem alterou o quê | T-11 |

### Eixo 2: Implementação

| ID | Vetor | Ameaça |
|---|---|---|
| V-05 | Busca por id sem verificar o dono do registro (BOLA) | T-07, T-10 |
| V-06 | Schemas de entrada aceitam campos extras (mass assignment) | T-08 |
| V-07 | Campo `motivo` sem validação por whitelist e regex | T-09 |
| V-08 | Dado de usuário renderizado sem escape (XSS stored) | T-19, T-20 |
| V-09 | Senha sem hash forte, JWT sem expiração ou sem verificação de assinatura | T-03, T-04 |

### Eixo 3: Infraestrutura

| ID | Vetor | Ameaça |
|---|---|---|
| V-10 | CORS com wildcard permite que qualquer site use a API no navegador do usuário | T-20 |
| V-11 | Sem HSTS, `X-Frame-Options` e `X-Content-Type-Options` | T-22 |
| V-12 | Sem rate limiting: força bruta no login e flood | T-01, T-12, T-18 |
| V-13 | Credenciais no código ou em `.env` versionado | T-15 |
| V-14 | Dependência vulnerável e pipeline sem análise de segurança | Supply chain |

## 5. Decisões que esta visão orienta

- **Autorização:** V-01, V-02 e V-05 pedem RBAC para os três papéis somados a ownership por recurso.
- **Laboratório:** entra por B1 como cliente de máquina, com credencial e escopo mínimo próprios (V-03).
- **Controles centralizados:** P2 concentra CORS, cabeçalhos e rate limiting. P5 concentra autenticação, autorização e ownership. Isso evita duplicar lógica de segurança nas rotas.
