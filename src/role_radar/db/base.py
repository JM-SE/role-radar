"""Base declarativa compartida por los modelos ORM."""

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Base declarativa única de role-radar."""
