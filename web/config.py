from pydantic import SecretStr
from starlette.config import Config

config = Config(".env")

DATABASE_URL: SecretStr = config("DATABASE_URL", cast=SecretStr)
SESSION_SECRET: SecretStr = config("SESSION_SECRET", cast=SecretStr)
WEBAUTHN_RP_NAME: str = config("WEBAUTHN_RP_NAME", cast=str)
WEBAUTHN_RP_ID: str = config("WEBAUTHN_RP_ID", cast=str)
