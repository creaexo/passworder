from dataclasses import dataclass
from datetime import datetime
from pydantic import BaseModel, Field

@dataclass(frozen=True)
class User:
    id: int | None
    username: str
    password_hash: str
    created_at: datetime

@dataclass(frozen=True)
class PasswordEntry:
    id: int | None
    user_id: int
    service: str
    login: str
    encrypted_password: bytes
    salt: bytes
    iv: bytes
    created_at: datetime
    updated_at: datetime

class UserCreate(BaseModel):
    username: str = Field(..., description="Unique username")
    master_password: str = Field(..., description="Master password for encryption key derivation")

class UserRead(BaseModel):
    id: int
    username: str
    created_at: datetime

class PasswordEntryCreate(BaseModel):
    service: str = Field(..., description="Name of the service or application")
    login: str = Field(..., description="Login or email")
    password: str = Field(..., description="Plaintext password; will be encrypted before storage")

class PasswordEntryRead(BaseModel):
    id: int
    service: str
    login: str
    created_at: datetime
    updated_at: datetime
