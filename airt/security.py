"""Password hashing, API keys, session tokens and credential encryption (no external auth deps)."""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
from typing import Any

from cryptography.fernet import Fernet, InvalidToken
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from .config import get_settings

API_KEY_PREFIX = "airt_"
_PBKDF2_ROUNDS = 390_000


# --- passwords -------------------------------------------------------------
def hash_password(password: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _PBKDF2_ROUNDS)
    return f"pbkdf2_sha256${_PBKDF2_ROUNDS}${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algo, rounds, salt_b64, dk_b64 = encoded.split("$")
        if algo != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), base64.b64decode(salt_b64), int(rounds))
        return hmac.compare_digest(dk, base64.b64decode(dk_b64))
    except Exception:
        return False


# --- agent API keys ----------------------------------------------------------
def generate_api_key() -> str:
    return API_KEY_PREFIX + secrets.token_urlsafe(32)


def hash_api_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def api_key_prefix(key: str) -> str:
    return key[: len(API_KEY_PREFIX) + 6]


# --- reviewer sessions --------------------------------------------------------
def _serializer() -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(get_settings().secret_key, salt="airt-session")


def create_session_token(data: dict[str, Any]) -> str:
    return _serializer().dumps(data)


def read_session_token(token: str) -> dict[str, Any] | None:
    try:
        return _serializer().loads(token, max_age=get_settings().session_max_age_seconds)
    except (BadSignature, SignatureExpired):
        return None


# --- upstream credential encryption --------------------------------------------
def _fernet() -> Fernet:
    return Fernet(get_settings().fernet_key)


def encrypt_secret(value: str | None) -> str | None:
    if not value:
        return None
    return _fernet().encrypt(value.encode()).decode()


def decrypt_secret(token: str | None) -> str | None:
    if not token:
        return None
    try:
        return _fernet().decrypt(token.encode()).decode()
    except InvalidToken:
        return None


# --- header redaction -----------------------------------------------------------
SENSITIVE_HEADERS = {"authorization", "x-api-key", "x-airt-key", "cookie", "set-cookie", "proxy-authorization", "x-goog-api-key", "api-key"}


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    out = {}
    for k, v in headers.items():
        if k.lower() in SENSITIVE_HEADERS:
            out[k] = (v[:10] + "[redacted]") if len(v) > 10 else "[redacted]"
        else:
            out[k] = v
    return out
