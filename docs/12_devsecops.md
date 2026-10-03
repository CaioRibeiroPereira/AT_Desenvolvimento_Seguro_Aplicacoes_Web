# Exercício 12: Pipeline DevSecOps e auditoria automatizada

## 1. Em que fase do SDLC cada ferramenta atua

| Ferramenta | Tipo | Fase | Por quê, neste projeto |
|---|---|---|---|
| Bandit | SAST | Commit/build, todo push e PR | Analisa o código sem precisar da aplicação rodando e encontra padrões inseguros mais cedo, como senhas no código ou funções perigosas. Não identifica falhas de lógica de autorização, como a BOLA do Ex8. |
| pip-audit | SCA | Build, todo push e PR | Verifica o `requirements.txt` em busca de vulnerabilidades conhecidas nas dependências, como FastAPI, SQLModel e PyJWT. É rápido e não precisa da aplicação rodando. |
| pytest (funcional + autorização) | Mais próximo de IAST neste projeto | Teste de integração, todo push e PR | Executa a aplicação e testa autenticação, autorização e outros fluxos. Foi esse tipo de teste que ajudou a identificar problemas como a BOLA e o risco T-14, que não seriam encontrados pelo SAST. |
| OWASP ZAP | DAST | Staging/pré-deploy, não a cada commit | Precisa da aplicação rodando para fazer requisições HTTP reais. Por ser mais lento, fica para a auditoria final (Ex13), antes do deploy. |

## 2. Priorização das vulnerabilidades do Assessment

| # | Vulnerabilidade | CVSS | Vetor | Ativo | Impacto de negócio | Status | Prioridade |
|---|---|---|---|---|---|---|---|
| 1 | Agenda sem autenticação (T-21) | 7.5 | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N | A1 | Alto | Corrigido (Ex9) | Crítica |
| 2 | BOLA em leitura de consulta (T-07) | 6.5 | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N | A1 | Alto | Corrigido (Ex9) | Alta |
| 3 | XSS stored no campo `motivo` (T-19) | 5.4 | AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N | A1 | Alto | Mitigado (Ex2), reforçado (Ex9) | Alta |
| 4 | Mass assignment (T-08) | 6.5 | AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N | A2, A5 | Médio | Corrigido (Ex9) | Média-Alta |
| 5 | Cabeçalhos ausentes / clickjacking (T-22) | 5.4 | AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N | A1 | Médio | Corrigido (Ex10) | Média |
| 6 | Sem rate limiting no login (T-01) | 5.3 | AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N | A3 | Médio | Corrigido (Ex10) | Média |
| 7 | Rate limiting M2M só por IP (T-18) | 5.3 | AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L | A6 | Baixo | Parcial | Baixa |
| 8 | Sem trilha de auditoria (T-11) | 4.3 | AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N | A2 | Médio | Corrigido (Ex13) | Média |
| 9 | 403 vs 404 permite mapear ids (T-14) | — | (não é uma falha isolada, é um trade-off de design) | A1 | Médio | Parcial, descoberto no Ex12 | Média |

Os resultados mostram que a ordem das correções dos Ex9 e Ex10 foi compatível com as vulnerabilidades de maior prioridade. Os itens que continuam abertos ou parciais têm impacto médio ou baixo. Por isso, eles não bloqueiam o projeto neste momento e serão revisados no relatório final (Ex13).

## 3. Security Gate no GitHub Actions

O arquivo `.github/workflows/security.yml` possui três verificações que rodam em paralelo a cada push ou PR na `main`: Bandit, pip-audit e pytest.

Depois delas, o `security-gate` só é executado se as três forem aprovadas. Assim, qualquer falha impede a aprovação do pipeline.

O Bandit bloqueia problemas de severidade média ou maior. Os quatro problemas encontrados atualmente são de baixa severidade e são falsos positivos relacionados a strings como "bearer" e "client_credentials". Por isso, não bloqueiam o pipeline.

O pip-audit bloqueia qualquer vulnerabilidade conhecida nas dependências. Na execução atual, nenhuma vulnerabilidade foi encontrada.

O pytest bloqueia o pipeline se qualquer teste falhar, incluindo os testes de autorização.

O pipeline foi executado no GitHub Actions após o push e terminou com sucesso, com os quatro jobs aprovados.

## 4. Testes de autorização expandidos (Ex12)

O arquivo `tests/test_ex12_seguranca.py` adiciona testes para problemas identificados no threat model:

- **T-04 — JWT adulterado:** altera o `role` do token sem refazer a assinatura. O token é rejeitado com 401, pois a assinatura não corresponde mais ao conteúdo.
- **T-04 — JWT expirado:** um token válido, mas com data de expiração passada, também é rejeitado com 401.
- **T-14 — Enumeração de IDs:** o teste registra um risco existente. Quando uma consulta existe, mas não pertence ao usuário, a API retorna 403. Quando ela não existe, retorna 404. Essa diferença permite que um usuário autenticado descubra quais IDs existem, mesmo sem conseguir acessar os dados.
- **Escrita e forja de token (T-04, T-08, T-10 e T-13):** token forjado com outra chave é rejeitado com 401 (T-04 / MC-07); profissional não altera nem apaga consulta de outro profissional, nem cria consulta para outro `profissional_id` (T-10 / MC-01); recepcionista não altera nem apaga consulta (T-13 / MC-05); mass assignment com `created_by` no PATCH retorna 422 e não altera o valor no banco (T-08 / MC-06); escrita sem token retorna 401 (MC-01).

A diferença entre 403 e 404 foi mantida de forma consciente. Alterá-la poderia mudar um comportamento já definido desde o Ex9.

**Evidências:**
