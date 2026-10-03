# Exercício 12: Pipeline DevSecOps e auditoria automatizada

## 1. Em que fase do SDLC cada ferramenta atua

| Ferramenta | Tipo | Fase | Por quê, neste projeto |
|---|---|---|---|
| Bandit | SAST | Commit/build, todo push e PR | Lê o código fonte sem precisar da app rodando. Pega padrões perigosos cedo (shift-left): segredo hardcoded, uso de função insegura. Não teria pego a BOLA do Ex8, porque é uma falha de lógica de autorização, não um padrão de código. |
| pip-audit | SCA | Build, todo push e PR | Verifica `requirements.txt` contra CVEs conhecidas (ex.: FastAPI, SQLModel, python-jose). Roda rápido, não depende da app no ar, então cabe no mesmo estágio do SAST. |
| pytest (funcional + autorização) | O mais próximo de IAST nesta escala de projeto | Teste de integração, todo push e PR | Não é uma ferramenta IAST comercial, mas exercita o código real em execução (FastAPI + banco real de teste), incluindo os fluxos de autenticação e autorização. É esse tipo de teste que achou a BOLA original (Ex8, via exploração manual) e o risco residual do T-14 (Ex12, via teste guiado pelo threat model) — nenhum SAST pegaria essas duas coisas. |
| OWASP ZAP | DAST | Staging/pré-deploy, não a cada commit | Precisa da aplicação rodando e respondendo a requisições HTTP reais; é mais lento e exige ambiente no ar, então não cabe em todo push. Fica para a auditoria final (Ex13), simulando a etapa de pré-deploy do pipeline. |

## 2. Priorização das vulnerabilidades do Assessment

Score CVSS v3.1 base, vetor, ativo afetado (ver `04_threat_model.md`) e critério de impacto de negócio (Alto: expõe dado de paciente A1 ou viola LGPD diretamente; Médio: afeta operação/credenciais sem expor dado de paciente; Baixo: afeta só disponibilidade de controle complementar).

| # | Vulnerabilidade | CVSS | Vetor | Ativo | Impacto de negócio | Status | Prioridade |
|---|---|---|---|---|---|---|---|
| 1 | Agenda sem autenticação (T-21) | 7.5 | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N | A1 | Alto | Corrigido (Ex9) | Crítica |
| 2 | BOLA em leitura de consulta (T-07) | 6.5 | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N | A1 | Alto | Corrigido (Ex9) | Alta |
| 3 | XSS stored no campo motivo (T-19) | 5.4 | AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N | A1 | Alto | Mitigado (Ex2), reforçado (Ex9) | Alta |
| 4 | Mass assignment (T-08) | 6.5 | AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N | A2, A5 | Médio | Corrigido (Ex9) | Média-Alta |
| 5 | Cabeçalhos ausentes / clickjacking (T-22) | 5.4 | AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N | A1 | Médio | Corrigido (Ex10) | Média |
| 6 | Sem rate limiting no login (T-01) | 5.3 | AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N | A3 | Médio | Corrigido (Ex10) | Média |
| 7 | Rate limiting M2M só por IP (T-18) | 5.3 | AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L | A6 | Baixo | Parcial | Baixa |
| 8 | Sem trilha de auditoria (T-11) | 4.3 | AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N | A2 | Médio | Aberto | Média |
| 9 | 403 vs 404 permite mapear ids (T-14) | — | (não é uma falha isolada, é um trade-off de design) | A1 | Médio | Parcial, descoberto no Ex12 | Média |

Os scores confirmam, em retrospecto, que a ordem de correção seguida nos exercícios (Ex9 primeiro, depois Ex10) bateu com as prioridades mais altas (#1 a #6). Os itens que seguem abertos ou parciais (#7, #8, #9) têm impacto de negócio médio ou baixo, o que embasa a decisão de não bloquear o projeto por eles neste momento — essa decisão é revisitada no relatório final (Ex13).

## 3. Security gate no GitHub Actions

Arquivo: `.github/workflows/security.yml`. Três jobs (`sast`, `sca`, `tests`) rodam em paralelo a cada push/PR na `main`; um quarto job (`security-gate`) só executa se os três passarem (`needs: [sast, sca, tests]`) — é esse encadeamento que bloqueia o merge quando qualquer um falha.

**Critério de severidade definido:**
- **Bandit:** bloqueia em severidade **Média ou superior**, com confiança Média ou superior (`-ll -ii`). Rodei localmente contra o código atual: 4 achados, todos severidade Low (falsos positivos do tipo "possible hardcoded password" em cima de strings como `"bearer"` e `"client_credentials"`) — nenhum bloquearia o gate hoje. Severidade Low fica de fora do gate de propósito, porque bloquear nela geraria ruído alto sem achado real, e a equipe passaria a ignorar o pipeline.
- **pip-audit:** bloqueia em **qualquer CVE conhecida**, sem piso de severidade. Diferente do código-próprio, uma dependência vulnerável em produção não depende de a equipe ter escrito o bug — e o dado tratado é de saúde, então a tolerância a dependência vulnerável é zero. Rodei localmente: nenhuma vulnerabilidade encontrada nas dependências atuais.
- **pytest:** qualquer teste falhando bloqueia, sem exceção, incluindo a suíte de autorização.

## 4. Testes de autorização expandidos (Ex12)

`tests/test_ex12_seguranca.py` expande o teste iniciado no Ex6, cobrindo vetores do threat model do Ex4 que ainda não tinham teste:

- **T-04 (JWT adulterado):** token com o claim `role` trocado para `admin`, sem reassinar — rejeitado (401), porque a assinatura não bate mais.
- **T-04 (JWT expirado):** token assinado corretamente mas com `exp` no passado — rejeitado (401).
- **T-14 (enumeração de ids):** o teste não prova uma correção — documenta um risco residual real: `403` (consulta existe, mas não é sua) e `404` (consulta não existe) são respostas diferentes, então um usuário autenticado consegue, por tentativa, descobrir quais ids de consulta existem, mesmo sem conseguir ler o conteúdo. Decisão consciente: não uniformizado agora, porque mudar para 404 uniforme alteraria o comportamento já testado e documentado desde o Ex9, trocando clareza de erro por um ganho de sigilo marginal (o atacante já precisa estar autenticado). Fica registrado como risco residual para a decisão final do Ex13.

Suíte completa após o Ex12: **30 testes passando**.
