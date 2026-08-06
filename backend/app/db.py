"""Database engine and session handling."""

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import NullPool

from .models import Base


class Database:
    def __init__(self, url: str):
        is_sqlite = url.startswith("sqlite")
        # SQLite is only used by the test suite, which builds a fresh engine per
        # test. Pooling there leaves connections open on discarded engines, so
        # connections are closed as soon as they are returned instead.
        self.engine = create_engine(
            url,
            connect_args={"check_same_thread": False} if is_sqlite else {},
            poolclass=NullPool if is_sqlite else None,
            future=True,
        )
        self.session_factory = sessionmaker(
            bind=self.engine, expire_on_commit=False, future=True
        )

    def create_all(self) -> None:
        Base.metadata.create_all(self.engine)

    def session(self) -> Session:
        return self.session_factory()

    def dispose(self) -> None:
        self.engine.dispose()
