from pydantic import SecretStr
from starlette.config import Config

config = Config(".env")

DATABASE_URL: SecretStr = config("DATABASE_URL", cast=SecretStr)
SESSION_SECRET: SecretStr = config("SESSION_SECRET", cast=SecretStr)
