"""End-to-end tests for the /api/v1 JSON API."""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import tempfile
from pathlib import Path

import pytest

from app import create_app
from webapp.db import init_engine, make_session_factory, session_scope
from webapp.models import User


@pytest.fixture()
def app_with_token(monkeypatch):
    tmp = Path(tempfile.mkdtemp())
    db_url = f"sqlite:///{tmp / 'test.db'}"
    monkeypatch.setenv("DATABASE_URL", db_url)
    monkeypatch.setenv("SECRET_KEY", "x" * 40)
    monkeypatch.setenv("ADMIN_EMAIL", "admin@test")
    monkeypatch.setenv("ADMIN_PASSWORD", "adminpw")
    monkeypatch.setenv("UPLOAD_FOLDER", str(tmp / "uploads"))

    app = create_app()

    token = secrets.token_urlsafe(32)
    Session = make_session_factory(init_engine(db_url))
    with session_scope(Session) as s:
        s.add(
            User(
                email="cli@test",
                password_hash="x",
                api_token_hash=hashlib.sha256(token.encode()).hexdigest(),
            )
        )

    return app, token


def _h(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def test_requires_bearer_token(app_with_token):
    app, _ = app_with_token
    c = app.test_client()
    assert c.get("/api/v1/me").status_code == 401
    assert c.get("/api/v1/me", headers={"Authorization": "Bearer bogus"}).status_code == 401


def test_me_returns_identity(app_with_token):
    app, token = app_with_token
    c = app.test_client()
    r = c.get("/api/v1/me", headers=_h(token))
    assert r.status_code == 200
    body = r.get_json()
    assert body["email"] == "cli@test"
    assert body["is_admin"] is False


def test_did_create_returns_one_time_secrets(app_with_token):
    app, token = app_with_token
    c = app.test_client()
    r = c.post("/api/v1/dids", json={"company": "Acme"}, headers=_h(token))
    assert r.status_code == 201
    body = r.get_json()
    assert body["did"].startswith("did:prism:")
    assert len(body["privkey_hex"]) == 64
    assert body["passphrase"]
    assert body["kycStatus"] == "draft"


def test_full_lifecycle(app_with_token):
    app, token = app_with_token
    c = app.test_client()
    d = c.post("/api/v1/dids", json={"company": "Lifecycle Co"}, headers=_h(token)).get_json()

    # list shows it
    lst = c.get("/api/v1/dids", headers=_h(token)).get_json()
    assert len(lst) == 1 and lst[0]["id"] == d["id"]

    # issue VC
    POL = "a" * 56
    r = c.post(
        f"/api/v1/dids/{d['id']}/credentials",
        json={"label": "Test", "policy_id": POL, "privkey_hex": d["privkey_hex"]},
        headers=_h(token),
    )
    assert r.status_code == 201
    vc = r.get_json()
    assert vc["vc"]["proof"]["jws"]

    # list VCs
    vcs = c.get(f"/api/v1/dids/{d['id']}/credentials", headers=_h(token)).get_json()
    assert len(vcs) == 1 and vcs[0]["id"] == vc["id"]

    # metadata
    md = c.post(
        f"/api/v1/credentials/{vc['id']}/metadata",
        json={"privkey_hex": d["privkey_hex"], "description": "test"},
        headers=_h(token),
    )
    assert md.status_code == 200
    md_body = md.get_json()
    assert md_body["savedFilename"].endswith(".json")
    assert md_body["metadata"]["725"][POL]["Lifecycle Co"]["proof"]["signatureValue"]

    # revoke
    rv = c.post(
        f"/api/v1/credentials/{vc['id']}/revoke", json={"reason": "t"}, headers=_h(token)
    ).get_json()
    assert rv["status"] == "revoked"

    # metadata is now blocked
    md2 = c.post(
        f"/api/v1/credentials/{vc['id']}/metadata",
        json={"privkey_hex": d["privkey_hex"]},
        headers=_h(token),
    )
    assert md2.status_code == 409


def test_passphrase_signing_path(app_with_token):
    """Clients can supply the passphrase instead of raw privkey_hex."""
    app, token = app_with_token
    c = app.test_client()
    d = c.post("/api/v1/dids", json={"company": "Pass Co"}, headers=_h(token)).get_json()

    POL = "b" * 56
    r = c.post(
        f"/api/v1/dids/{d['id']}/credentials",
        json={"label": "ByPass", "policy_id": POL, "passphrase": d["passphrase"]},
        headers=_h(token),
    )
    assert r.status_code == 201, r.get_json()
    assert r.get_json()["vc"]["proof"]["jws"]


def test_cross_user_forbidden(app_with_token):
    app, token = app_with_token
    c = app.test_client()
    d = c.post("/api/v1/dids", json={"company": "Owner"}, headers=_h(token)).get_json()

    other = secrets.token_urlsafe(32)
    Session = make_session_factory(init_engine(os.environ["DATABASE_URL"]))
    with session_scope(Session) as s:
        s.add(
            User(
                email="intruder@test",
                password_hash="x",
                api_token_hash=hashlib.sha256(other.encode()).hexdigest(),
            )
        )

    r = c.get(f"/api/v1/dids/{d['id']}", headers=_h(other))
    assert r.status_code == 403


def test_missing_company_rejected(app_with_token):
    app, token = app_with_token
    c = app.test_client()
    r = c.post("/api/v1/dids", json={}, headers=_h(token))
    assert r.status_code == 400
    assert "company" in r.get_json()["error"]


def test_vc_needs_signing_key(app_with_token):
    app, token = app_with_token
    c = app.test_client()
    d = c.post("/api/v1/dids", json={"company": "NoKey"}, headers=_h(token)).get_json()
    r = c.post(
        f"/api/v1/dids/{d['id']}/credentials", json={"label": "x"}, headers=_h(token)
    )
    assert r.status_code == 400
    assert "privkey_hex" in r.get_json()["error"] or "passphrase" in r.get_json()["error"]
