from typing import Literal
from pydantic import BaseModel, Field

class Settings(BaseModel):
    # Server
    host: str = Field("0.0.0.0", description="API host")
    port: int = Field(8000, description="API port")

    # Database
    db_backend: Literal["postgresql", "sqlcipher"] = Field(
        "postgresql", description="Choose 'postgresql' or 'sqlcipher'"
    )
    postgres_dsn: str | None= Field(
        "postgresql://user:password@localhost:5432/passwords_db",
        description="PostgreSQL DSN"
    )
    sqlcipher_file: str | None= Field(
        "db/sqlcipher.sqlite",
        description="Path to SQLCipher-encrypted SQLite file"
    )

    # Crypto
    kdf_salt_size: int = Field(16, description="Salt size for KDF in bytes")
    kdf_iterations: int = Field(100_000, description="PBKDF2 iterations")
    encryption_algorithm: Literal["AESGCM"] = Field(
        "AESGCM", description="Symmetric encryption algorithm"
    )

    # Auth
    secret_key: str = Field(..., description="Secret key for JWT tokens")
    token_expire_minutes: int = Field(60 * 24, description="JWT expiration time")

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
