"""Password verification for the secure application.

``verify_password`` is called by the Flask server during login. It supports
the bcrypt hashes currently imported from Neon and Argon2id hashes if a
compatible record is introduced later.
"""

import bcrypt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError


PASSWORD_HASHER = PasswordHasher()
BCRYPT_PREFIXES = ("$2a$", "$2b$", "$2y$")


def verify_password(password_hash: str | None, password: str) -> bool:
    """Verify a password without ever storing or returning the plaintext value"""
    if not password_hash:
        return False

    if password_hash.startswith(BCRYPT_PREFIXES):
        try:
            return bcrypt.checkpw(
                password.encode("utf-8"), password_hash.encode("utf-8")
            )
        except (TypeError, ValueError):
            return False

    try:
        return PASSWORD_HASHER.verify(password_hash, password)
    except (InvalidHashError, VerificationError, VerifyMismatchError):
        return False
