from datetime import datetime
from collections.abc import AsyncGenerator

from sqlalchemy import ForeignKey, LargeBinary, String, Integer, select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker

from passworder.config import settings
from passworder.models import User, PasswordEntry


class Base(DeclarativeBase):
    pass


class UserModel(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(150), unique=True)
    password_hash: Mapped[bytes] = mapped_column(LargeBinary)
    created_at: Mapped[datetime] = mapped_column(default=datetime.now)
    entries: Mapped[list["PasswordEntryModel"]] = relationship(
        "PasswordEntryModel", back_populates="user"
    )


class PasswordEntryModel(Base):
    __tablename__ = "password_entries"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    service: Mapped[str] = mapped_column(String(200))
    login: Mapped[str] = mapped_column(String(200))
    encrypted_password: Mapped[bytes] = mapped_column(LargeBinary)
    salt: Mapped[bytes] = mapped_column(LargeBinary)
    iv: Mapped[bytes] = mapped_column(LargeBinary)
    """Initialization vector (IV) for AES-GCM. Must be unique per encryption."""

    created_at: Mapped[datetime] = mapped_column(default=datetime.now)
    updated_at: Mapped[datetime] = mapped_column(default=datetime.now, onupdate=datetime.now)
    user: Mapped[UserModel] = relationship(
        "UserModel", back_populates="entries"
    )


async def get_engine() -> AsyncEngine:
    """Create async engine based on configuration."""
    if settings.db_backend == "postgresql":
        url = settings.postgres_dsn.replace(
            "postgresql://", "postgresql+asyncpg://"
        )
    else:
        url = f"sqlite+aiosqlite:///{settings.sqlcipher_file}"
    return create_async_engine(url)


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """Yield a new asynchronous database session."""
    engine = await get_engine()
    async_session = sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )
    async with async_session() as session:
        yield session


class UserRepository:
    """Repository for user-related database operations."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def create(self, user: User) -> User:
        """Create a new user record."""
        record = UserModel(
            username=user.username,
            password_hash=user.password_hash.encode()
        )
        self.session.add(record)
        await self.session.flush()
        return User(
            id=record.id,
            username=record.username,
            password_hash=record.password_hash.decode(),
            created_at=record.created_at
        )

    async def get_by_username(self, username: str) -> User | None:
        """Fetch a user by username."""
        result = await self.session.execute(
            select(UserModel).where(UserModel.username == username)
        )
        user_record = result.scalar_one_or_none()
        if not user_record:
            return None
        return User(
            id=user_record.id,
            username=user_record.username,
            password_hash=user_record.password_hash.decode(),
            created_at=user_record.created_at
        )


class PasswordEntryRepository:
    """Repository for password entry database operations."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def create(self, entry: PasswordEntry) -> PasswordEntry:
        """Create a new password entry record."""
        record = PasswordEntryModel(
            user_id=entry.user_id,
            service=entry.service,
            login=entry.login,
            encrypted_password=entry.encrypted_password,
            salt=entry.salt,
            iv=entry.iv
        )
        self.session.add(record)
        await self.session.flush()
        return PasswordEntry(
            id=record.id,
            user_id=record.user_id,
            service=record.service,
            login=record.login,
            encrypted_password=record.encrypted_password,
            salt=record.salt,
            iv=record.iv,
            created_at=record.created_at,
            updated_at=record.updated_at
        )

    async def list_for_user(self, user_id: int) -> list[PasswordEntry]:
        """Retrieve all password entries for a specific user."""
        result = await self.session.execute(
            select(PasswordEntryModel).where(
                PasswordEntryModel.user_id == user_id
            )
        )
        entries = result.scalars().all()
        return [
            PasswordEntry(
                id=e.id,
                user_id=e.user_id,
                service=e.service,
                login=e.login,
                encrypted_password=e.encrypted_password,
                salt=e.salt,
                iv=e.iv,
                created_at=e.created_at,
                updated_at=e.updated_at
            )
            for e in entries
        ]
