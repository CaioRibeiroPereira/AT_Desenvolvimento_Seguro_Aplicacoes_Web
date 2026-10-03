# Exercício 11: Persistência segura

1. **Migração para SQLModel:** `Consulta`, `User` e `Client` passaram a ser tabelas em um banco SQLite (`app/database/session.py`). Antes, os dados ficavam em dicionários Python e eram perdidos ao reiniciar a aplicação.
2. **Sessão por requisição:** `get_session()`, com `Depends(get_session)`, abre e fecha a sessão do banco em cada requisição que acessa dados. As rotas não gerenciam conexões diretamente.
3. **Consultas parametrizadas:** o SQLModel usa recursos como `select()`, `session.get()` e `.where()` para gerar consultas parametrizadas, evitando concatenar dados do usuário em comandos SQL. Como antes não havia banco de dados, não existia uma camada SQL vulnerável para comparar.
4. **Configuração do banco:** `DATABASE_URL` é lida do `.env` por meio de `Settings`, em `app/config.py`, com um valor padrão para desenvolvimento. A conexão não fica fixa no código-fonte, e o `.env.example` não contém segredos reais.
5. **Criação das tabelas e dados iniciais:** `init_db()`, executado no `lifespan` em `app/main.py`, cria as tabelas e cadastra os usuários e o cliente M2M na primeira inicialização, sem sobrescrever dados existentes.
6. **Testes:** `tests/conftest.py` utiliza SQLite em memória com `StaticPool` e substitui `get_session` por meio de `app.dependency_overrides`. Os 27 testes existentes continuam passando sem mudanças no comportamento da aplicação.

**EVIDÊNCIAS**
