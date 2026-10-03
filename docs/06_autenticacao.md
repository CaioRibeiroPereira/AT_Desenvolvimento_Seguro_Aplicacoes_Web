# Exercício 6: Autenticação e autorização

## 1. O que foi implementado

- **Login com OAuth2PasswordBearer:** `POST /auth/login` recebe usuário e senha em formulário e devolve um JWT (`app/routes/auth.py`).
- **Hashing bcrypt:** senhas nunca são guardadas em texto plano. Só o hash bcrypt (com salt) fica no armazenamento (`app/auth/security.py`).
- **JWT com expiração:** o token carrega `sub`, `role`, `iat` e `exp` (30 minutos, configurável). A verificação exige `exp` e `sub` e aceita só o algoritmo HS256, o que rejeita tokens `alg: none`.
- **MFA simulado para admin:** a conta admin só recebe token se enviar, junto com a senha, o código MFA configurado em `.env`. A comparação usa `hmac.compare_digest`.
- **Erro de login genérico:** usuário inexistente e senha errada devolvem a mesma resposta, e um hash falso é verificado quando o usuário não existe, para igualar o tempo de resposta.
- **Segredos fora do código:** chave do JWT, código MFA e senhas iniciais vêm de `.env` via `BaseSettings`. O repositório só tem `.env.example`.
- **Camada única de segurança:** hashing e JWT em `app/auth/security.py`, dependências de autenticação e papéis em `app/auth/deps.py`, ownership em `app/auth/ownership.py`.

## 2. Modelo de autorização: RBAC mais ownership por recurso

| Papel | Consultas | Área admin |
|---|---|---|
| recepcionista | Lê a lista e a consulta por id. Não cria nem altera | Bloqueado |
| profissional | Cria e gerencia só consultas em que `profissional_id` é o seu | Bloqueado |
| admin | Cria e gerencia qualquer consulta | Acesso, com MFA |

**Por que RBAC:** o sistema tem exatamente três papéis fixos e as permissões seguem o papel. RBAC é simples de implementar (uma dependência `require_roles`), fácil de auditar e de testar.

**Por que ABAC não:** ABAC avalia regras sobre muitos atributos (horário, local, sensibilidade do dado). Aqui não há atributos além de papel e dono do registro, então a complexidade extra não se justifica.

**Por que só RBAC não basta:** o RBAC diz que um profissional pode alterar consultas, mas não diz de quem. A regra "profissional só gerencia consultas dos próprios pacientes" depende do recurso, então foi somada a verificação de ownership (`verificar_ownership`), que compara `consulta.profissional_id` com o `profissional_id` do usuário autenticado.

## 3. Proteção das rotas

| Rota | Exigência |
|---|---|
| `POST /auth/login` | Pública |
| `GET /admin/usuarios` | Papel admin |
| `POST /consultas` | Profissional (só para si) ou admin |
| `PUT`, `PATCH`, `DELETE /consultas/{id}` | Profissional dono ou admin, com ownership |
| `GET /consultas` e `GET /consultas/{id}` | Qualquer usuário autenticado |
| `GET /recepcao/agenda` | Ainda sem autenticação |

## 4. Limitações conhecidas nesta fase

- `GET /consultas/{id}` e `GET /consultas` exigem login, mas não checam o dono do registro. Um profissional autenticado consegue ler a consulta de outro profissional trocando o id (BOLA, ameaça T-07).
- A página `/recepcao/agenda` continua acessível sem autenticação (ameaça T-21).
- O armazenamento de usuários é em memória e as senhas iniciais vêm de variáveis de ambiente.

## 5. Teste automatizado

`tests/test_autorizacao.py` valida, entre outros casos, que recepcionista e profissional recebem 403 em `GET /admin/usuarios`, que a rota sem token retorna 401, que o login admin exige MFA e que um profissional não altera a consulta de outro.
