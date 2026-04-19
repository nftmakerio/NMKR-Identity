"""Thin HTTP client for the NMKR Identity platform.

Stdlib-only (urllib). Config lives at ``~/.nmkr-identity/config.json`` and can
be overridden via env vars ``NMKR_IDENTITY_URL`` / ``NMKR_IDENTITY_TOKEN``.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

DEFAULT_URL = "https://identity.nmkr.io"
CONFIG_DIR = Path(os.environ.get("NMKR_IDENTITY_HOME", str(Path.home() / ".nmkr-identity")))
CONFIG_PATH = CONFIG_DIR / "config.json"


class RemoteError(RuntimeError):
    def __init__(self, status: int, message: str, body: Any = None):
        super().__init__(f"HTTP {status}: {message}")
        self.status = status
        self.body = body


@dataclass
class Config:
    url: str = DEFAULT_URL
    token: Optional[str] = None

    @classmethod
    def load(cls) -> "Config":
        data: dict = {}
        if CONFIG_PATH.exists():
            try:
                data = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
            except Exception:
                data = {}
        return cls(
            url=(os.environ.get("NMKR_IDENTITY_URL") or data.get("url") or DEFAULT_URL).rstrip("/"),
            token=os.environ.get("NMKR_IDENTITY_TOKEN") or data.get("token"),
        )

    def save(self) -> None:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        CONFIG_PATH.write_text(
            json.dumps({"url": self.url, "token": self.token}, indent=2) + "\n",
            encoding="utf-8",
        )
        try:
            os.chmod(CONFIG_PATH, 0o600)
        except OSError:
            pass

    def clear_token(self) -> None:
        self.token = None
        if CONFIG_PATH.exists():
            try:
                data = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
            except Exception:
                data = {}
            data.pop("token", None)
            CONFIG_PATH.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


class Client:
    """Minimal REST client for the NMKR Identity v1 API."""

    def __init__(self, config: Optional[Config] = None, timeout: float = 30.0):
        self.cfg = config or Config.load()
        self.timeout = timeout

    # ---- HTTP plumbing ----

    def _request(self, method: str, path: str, *, body: Any = None, auth: bool = True) -> Any:
        url = f"{self.cfg.url.rstrip('/')}{path}"
        headers = {"Accept": "application/json"}
        if auth:
            if not self.cfg.token:
                raise RemoteError(401, "not logged in (set NMKR_IDENTITY_TOKEN or run `nmkr-identity remote login`)")
            headers["Authorization"] = f"Bearer {self.cfg.token}"
        data: Optional[bytes] = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read()
                if not raw:
                    return None
                ctype = resp.headers.get("Content-Type", "")
                if "application/json" in ctype:
                    return json.loads(raw)
                return raw.decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            raw = e.read() if hasattr(e, "read") else b""
            parsed: Any = None
            try:
                parsed = json.loads(raw) if raw else None
            except Exception:
                parsed = raw.decode("utf-8", errors="replace") if raw else None
            msg = ""
            if isinstance(parsed, dict):
                msg = parsed.get("error") or parsed.get("message") or ""
            raise RemoteError(e.code, msg or e.reason or "request failed", parsed) from None
        except urllib.error.URLError as e:
            raise RemoteError(0, f"connection failed: {e.reason}") from None

    # ---- account ----

    def whoami(self) -> dict:
        return self._request("GET", "/api/v1/me")

    # ---- DIDs ----

    def did_create(self, payload: dict) -> dict:
        return self._request("POST", "/api/v1/dids", body=payload)

    def did_list(self) -> list:
        return self._request("GET", "/api/v1/dids")

    def did_get(self, did_id: int) -> dict:
        return self._request("GET", f"/api/v1/dids/{did_id}")

    # ---- credentials ----

    def vc_issue(self, did_id: int, payload: dict) -> dict:
        return self._request("POST", f"/api/v1/dids/{did_id}/credentials", body=payload)

    def vc_list(self, did_id: int) -> list:
        return self._request("GET", f"/api/v1/dids/{did_id}/credentials")

    def vc_get(self, cred_id: int) -> dict:
        return self._request("GET", f"/api/v1/credentials/{cred_id}")

    def vc_revoke(self, cred_id: int, reason: Optional[str] = None) -> dict:
        return self._request("POST", f"/api/v1/credentials/{cred_id}/revoke", body={"reason": reason or ""})

    def vc_metadata(self, cred_id: int, payload: dict) -> dict:
        return self._request("POST", f"/api/v1/credentials/{cred_id}/metadata", body=payload)
