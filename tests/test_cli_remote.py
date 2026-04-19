"""Smoke tests for token_identity.remote.Client against the live test_client."""
from __future__ import annotations

import hashlib
import secrets
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from app import create_app
from token_identity.remote import Client, Config, RemoteError
from webapp.db import init_engine, make_session_factory, session_scope
from webapp.models import User


@pytest.fixture()
def running_app(monkeypatch):
    tmp = Path(tempfile.mkdtemp())
    db_url = f"sqlite:///{tmp / 'test.db'}"
    monkeypatch.setenv("DATABASE_URL", db_url)
    monkeypatch.setenv("SECRET_KEY", "x" * 40)
    monkeypatch.setenv("ADMIN_EMAIL", "admin@t")
    monkeypatch.setenv("ADMIN_PASSWORD", "x")
    monkeypatch.setenv("UPLOAD_FOLDER", str(tmp / "up"))

    app = create_app()
    token = secrets.token_urlsafe(32)
    Session = make_session_factory(init_engine(db_url))
    with session_scope(Session) as s:
        s.add(User(email="c@t", password_hash="x", api_token_hash=hashlib.sha256(token.encode()).hexdigest()))
    return app, token


def _patched_request(app):
    """Build a urllib.request.urlopen replacement that routes through app.test_client()."""
    test_client = app.test_client()

    class _FakeResponse:
        def __init__(self, resp):
            self._resp = resp
            self.status = resp.status_code
            self.headers = {"Content-Type": resp.headers.get("Content-Type", "")}

        def read(self):
            return self._resp.data

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

    def fake_urlopen(req, timeout=None):
        # urllib.Request → flask test client request
        method = req.get_method()
        url = req.full_url.split("://", 1)[-1].split("/", 1)[1]  # strip host
        path = "/" + url
        body = req.data
        headers = dict(req.header_items())
        resp = test_client.open(path, method=method, data=body, headers=headers)
        if resp.status_code >= 400:
            import urllib.error

            err = urllib.error.HTTPError(req.full_url, resp.status_code, resp.status, resp.headers, None)
            err.read = lambda: resp.data  # type: ignore[assignment]
            raise err
        return _FakeResponse(resp)

    return fake_urlopen


def test_remote_client_did_create(running_app, monkeypatch):
    app, token = running_app
    cfg = Config(url="http://fake.local", token=token)
    client = Client(cfg)

    with patch("urllib.request.urlopen", side_effect=_patched_request(app)):
        assert client.whoami()["email"] == "c@t"

        did = client.did_create({"company": "Remote Co"})
        assert did["did"].startswith("did:prism:")
        assert did["privkey_hex"] and did["passphrase"]

        POL = "c" * 56
        vc = client.vc_issue(did["id"], {"label": "L", "policy_id": POL, "privkey_hex": did["privkey_hex"]})
        assert vc["vc"]["proof"]["jws"]

        md = client.vc_metadata(vc["id"], {"privkey_hex": did["privkey_hex"]})
        assert md["metadata"]["725"][POL]

        rv = client.vc_revoke(vc["id"], reason="t")
        assert rv["status"] == "revoked"


def test_remote_client_requires_token():
    cfg = Config(url="http://x", token=None)
    with pytest.raises(RemoteError) as exc:
        Client(cfg).whoami()
    assert exc.value.status == 401
