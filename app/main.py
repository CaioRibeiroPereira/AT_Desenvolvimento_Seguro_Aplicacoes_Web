from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from app.config import settings
from app.database import init_db
from app.rate_limit import limiter
from app.routes import admin, auth, consultas, recepcao, slots


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


em_producao = settings.environment == "production"

app = FastAPI(
    title="API de Agendamento Clinico",
    description="API REST para agendamento de consultas medicas.",
    version="0.1.0",
    lifespan=lifespan,
    docs_url=None if em_producao else "/docs",
    openapi_url=None if em_producao else "/openapi.json",
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

# allowlist explicita: nunca "*". Origem precisa estar em ALLOWED_ORIGINS (.env).
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


app.include_router(auth.router)
app.include_router(admin.router)
app.include_router(consultas.router)
app.include_router(recepcao.router)
app.include_router(slots.router)


@app.get("/health", tags=["infra"])
def health_check() -> dict:
    return {"status": "ok"}
