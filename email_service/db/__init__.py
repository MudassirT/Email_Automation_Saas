"""
Database layer for AutoMail AI SaaS.
Provides SQLAlchemy 2.0 async models, database engine sessions,
and migration utilities.
"""

from .models import (  # noqa: F401
    set_encryption_context,
    clear_encryption_context,
    get_encryption_context,
    EncryptedTextField,
)
