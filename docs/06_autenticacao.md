# Exercício 6: Autenticação e autorização

**Autenticação:** O login usa OAuth2PasswordBearer e devolve um JWT (HS256) com `sub`, `role` e `exp`, que expira em 30 minutos. A verificação aceita só o algoritmo esperado, rejeitando tokens adulterados. As senhas ficam apenas como hash bcrypt, nunca em texto plano, e o erro de login é o mesmo para usuário inexistente e senha errada.

**MFA por usuário (TOTP):** O admin só recebe token se enviar, com a senha, o código de 6 dígitos do seu autenticador (TOTP, RFC 6238). Cada conta admin tem um segredo próprio, gerado no seed e guardado no banco.

**Segredos:** Chave do JWT e senhas iniciais vêm do `.env` via `BaseSettings`, e o projeto entrega só o `.env.example`. Os segredos TOTP ficam no banco, por usuário.

**Autorização:** RBAC com ownership. Há três papéis fixos, então o RBAC é simples e fácil de auditar. O ABAC não foi usado porque não há atributos além de papel e dono do registro. O RBAC sozinho não diz de quem é a consulta, por isso foi somada a verificação de ownership: o profissional só gerencia consultas com o seu `profissional_id`, o admin gerencia qualquer uma e o recepcionista não cria nem altera.

**Contas de demonstração (ambiente local, não usadas em produção):** as senhas iniciais são definidas pelas variáveis `SEED_*_PASSWORD` do `.env`, cujo modelo está em `.env.example`. Nenhuma senha fica versionada no repositório.

| Usuário | Papel | Observação |
|---|---|---|
| admin | admin | Exige MFA (código TOTP do autenticador) |
| dr_silva | profissional | `profissional_id` 10 |
| dr_souza | profissional | `profissional_id` 20 |
| recepcao | recepcionista | Só leitura de consultas |

**Teste:** O pytest valida que recepcionista e profissional recebem 403 na rota admin, que sem token o retorno é 401 e que o login do admin exige MFA.

**Limitação:** A leitura por id ainda não checa o dono do registro, e a agenda da recepção continua sem autenticação.

## Evidências

- Credenciais de demonstração do `.env`
- **1. Login retornando JWT:** em `POST /auth/login` entrei com as credenciais do dr_silva. Login bem-sucedido, a API devolve um JWT que identifica o usuário nas próximas requisições.
- **2. Rota protegida negando sem token:** executei sem estar autenticado e o resultado foi 401.
- **3. Usuário sem papel admin bloqueado:** loguei como dr_silva e executei `GET /admin/usuarios`. A saída foi erro 403 (acesso negado), por não ser administrador.
- **4. Teste com e sem MFA:**
  - Sem MFA: `{"detail":"Codigo MFA invalido ou ausente"}`. A senha estava certa, mas o login foi negado por falta do código.
  - Com o código TOTP do autenticador: devolveu o `access_token` do admin.
- **5. Pytest**
