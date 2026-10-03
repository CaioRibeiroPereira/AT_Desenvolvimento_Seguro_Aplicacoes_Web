from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    secret_key: str = Field(min_length=32)
    access_token_expire_minutes: int = 30
    mfa_code: str
    seed_admin_password: str
    seed_dr_silva_password: str
    seed_dr_souza_password: str
    seed_recepcionista_password: str
    lab_client_id: str
    lab_client_secret: str
    client_token_expire_minutes: int = 15
    allowed_origins: str = "http://localhost:3000,http://127.0.0.1:3000"
    database_url: str = "sqlite:///./clinica.db"

    @property
    def allowed_origins_list(self) -> list[str]:
        return [origin.strip() for origin in self.allowed_origins.split(",") if origin.strip()]


settings = Settings()
