from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Server
    host: str = Field(default="0.0.0.0", description="API host")
    port: int = Field(default=8000, description="API port")

    # Database
    db_backend: Literal["postgresql", "sqlcipher"] = Field(
        default="postgresql", description="Choose 'postgresql' or 'sqlcipher'"
    )
    postgres_dsn: str | None= Field(
        default="postgresql://user:password@localhost:5432/passwords_db",
        description="PostgreSQL DSN"
    )
    sqlcipher_file: str | None= Field(
        default="db/sqlcipher.sqlite",
        description="Path to SQLCipher-encrypted SQLite file"
    )

    # Crypto
    kdf_salt_size: int = Field(default=16, description="Salt size for KDF in bytes")
    kdf_iterations: int = Field(default=100_000, description="PBKDF2 iterations")
    encryption_algorithm: Literal["AESGCM"] = Field(
        default="AESGCM", description="Symmetric encryption algorithm"
    )


    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

settings = Settings()
