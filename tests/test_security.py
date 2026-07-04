"""Unit tests for password hashing and JWTs — no database needed."""

import uuid

import jwt
import pytest

from argus.core.security import (
    create_access_token,
    decode_access_token,
    hash_password,
    verify_password,
)


def test_password_roundtrip():
    h = hash_password("correct horse battery staple")
    assert h != "correct horse battery staple"  # never stored in plaintext
    assert verify_password(h, "correct horse battery staple")
    assert not verify_password(h, "wrong password")


def test_token_roundtrip():
    uid, tid = uuid.uuid4(), uuid.uuid4()
    token = create_access_token(user_id=uid, tenant_id=tid, role="analyst")
    claims = decode_access_token(token)
    assert claims["sub"] == str(uid)
    assert claims["tid"] == str(tid)
    assert claims["role"] == "analyst"


def test_expired_token_rejected():
    token = create_access_token(
        user_id=uuid.uuid4(), tenant_id=uuid.uuid4(), role="analyst", expires_minutes=-1
    )
    with pytest.raises(jwt.ExpiredSignatureError):
        decode_access_token(token)


def test_tampered_token_rejected():
    token = create_access_token(user_id=uuid.uuid4(), tenant_id=uuid.uuid4(), role="analyst")
    with pytest.raises(jwt.InvalidTokenError):
        decode_access_token(token[:-2] + "xx")
