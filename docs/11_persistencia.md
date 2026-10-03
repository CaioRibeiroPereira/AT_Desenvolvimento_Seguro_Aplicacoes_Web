# Exercício 11: Persistência segura

## 1. Migração para SQLModel

`Consulta`, `User` e `Client` viraram tabelas SQLModel (`table=True`), com SQLite como banco (`app/database/session.py`). Antes, tudo vivia em dicts Python em memória, perdidos a cada reinício do processo.

## 2. Sessão via injeção de dependência

`get_session()` (em `app/database/session.py`) abre e fecha a sessão por requisição, injetada com `Depends(get_session)` em toda rota que acessa dados — mesmo padrão de dependency injection já usado para autenticação desde o Ex6. Nenhuma rota abre conexão com o banco por conta própria.

## 3. Queries sempre parametrizadas

Todo acesso a dado usa o query builder do SQLModel (`select(...)`, `session.get(...)`, `.where(...)`), que gera SQL parametrizado nos bastidores — em nenhum lugar do código um valor de usuário é concatenado numa string SQL. Exemplos:

```python
session.exec(select(User).where(User.username == claims["sub"])).first()
session.get(Consulta, consulta_id)
query = select(Consulta).where(Consulta.profissional_id == user.profissional_id)
```

Como a aplicação nunca teve uma camada SQL antes deste exercício (Ex1 a Ex10 usavam dict em memória), não existe um "antes" vulnerável a SQL injection para comparar — a camada de persistência já nasce parametrizada.

## 4. Credenciais via BaseSettings e .env

`DATABASE_URL` é lido do `.env` via `Settings` (`app/config.py`), com valor padrão de desenvolvimento (`sqlite:///./clinica.db`). Nenhuma string de conexão fica hardcoded no código-fonte. O `.env.example` traz a variável sem segredo real.

## 5. Criação de tabelas e seed

`init_db()` roda no `lifespan` da aplicação (`app/main.py`): cria as tabelas (`SQLModel.metadata.create_all`) e popula os usuários e o cliente M2M na primeira subida, sem sobrescrever dados já existentes.

## 6. Testes

`tests/conftest.py` usa um SQLite em memória com `StaticPool` (uma única conexão compartilhada durante toda a suíte), sobrescrevendo `get_session` via `app.dependency_overrides`. Os 27 testes já existentes continuam passando sem alteração de comportamento — só a camada de armazenamento por baixo mudou.
