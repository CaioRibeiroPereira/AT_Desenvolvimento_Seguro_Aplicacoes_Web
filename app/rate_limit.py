from slowapi import Limiter
from slowapi.util import get_remote_address

# instancia unica, importada tanto pelo main.py (registro global)
# quanto pelas rotas que precisam de um limite diferenciado (ex.: login).
limiter = Limiter(key_func=get_remote_address, default_limits=["100/minute"])
