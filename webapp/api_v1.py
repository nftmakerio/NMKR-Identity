"""JSON API v1 for programmatic clients (CLI, agents, third-party tools).

All endpoints authenticate via ``Authorization: Bearer <token>`` where the
token is hashed against ``User.api_token_hash`` (the same hash stored by
``/settings/token``). No cookie/session auth on this surface — tokens only.
"""
from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime
from functools import wraps
from typing import Any, Callable, Optional

from flask import Flask, g, jsonify, request
from jsonschema import validate as jsonschema_validate
from sqlalchemy import select

from token_identity.models import TokenIdentity
from token_identity.prism_did import PrismDIDManager

from .crypto_utils import decrypt_with_passphrase, encrypt_with_passphrase
from .db import session_scope
from .models import AuditLog, Attestation, Credential, DidRecord, User


def _error(message: str, status: int = 400, **extra: Any):
    payload = {"error": message}
    payload.update(extra)
    return jsonify(payload), status


def register(app: Flask, Session) -> None:  # noqa: N803 (Session is a sessionmaker)
    """Mount /api/v1/* endpoints onto the given Flask app."""

    def _authenticate() -> Optional[dict]:
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return None
        token = auth.split(" ", 1)[1].strip()
        if not token:
            return None
        tok_hash = hashlib.sha256(token.encode()).hexdigest()
        with session_scope(Session) as s:
            u = s.scalar(select(User).where(User.api_token_hash == tok_hash))
            if not u:
                return None
            return {"id": u.id, "email": u.email, "is_admin": bool(u.is_admin)}

    def require_token(fn: Callable):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            user = _authenticate()
            if not user:
                return _error("unauthorized — provide a Bearer API token", status=401)
            g.api_user = user
            return fn(*args, **kwargs)

        return wrapper

    def _json_body() -> dict:
        if not request.data:
            return {}
        try:
            body = request.get_json(force=True, silent=False)
        except Exception:
            return {}
        return body if isinstance(body, dict) else {}

    def _base_url() -> str:
        return (app.config.get("BASE_URL") or request.host_url.rstrip("/")).rstrip("/")

    def _resolve_privkey(rec: DidRecord, body: dict) -> Optional[bytes]:
        """Return raw 32-byte private key material from body.privkey_hex or body.passphrase."""
        if body.get("privkey_hex"):
            try:
                return bytes.fromhex(body["privkey_hex"].strip())
            except Exception:
                return None
        if body.get("passphrase") and rec.project_privkey_encrypted:
            try:
                return decrypt_with_passphrase(body["passphrase"], rec.project_privkey_encrypted)
            except Exception:
                return None
        return None

    def _serialize_did(rec: DidRecord) -> dict:
        return {
            "id": rec.id,
            "did": rec.did_id,
            "company": rec.company,
            "website": rec.website,
            "twitter": rec.twitter,
            "discord": rec.discord,
            "kycStatus": rec.kyc_status,
            "createdAt": rec.created_at.isoformat() + "Z" if rec.created_at else None,
        }

    def _serialize_cred(c: Credential) -> dict:
        return {
            "id": c.id,
            "label": c.label,
            "status": c.status,
            "didRecordId": c.did_record_id,
            "createdAt": c.created_at.isoformat() + "Z" if c.created_at else None,
            "revokedAt": c.revoked_at.isoformat() + "Z" if c.revoked_at else None,
        }

    # -------- account --------

    @app.get("/api/v1/me")
    @require_token
    def api_v1_me():
        return jsonify(g.api_user)

    # -------- DIDs --------

    @app.post("/api/v1/dids")
    @require_token
    def api_v1_did_create():
        body = _json_body()
        company = (body.get("company") or "").strip()
        if not company:
            return _error("`company` is required")

        social: dict = {}
        tw = body.get("twitter") or []
        dc = body.get("discord") or []
        if isinstance(tw, str):
            tw = tw.split()
        if isinstance(dc, str):
            dc = dc.split()
        if tw:
            social["twitter"] = [h for h in tw if h]
        if dc:
            social["discord"] = [h for h in dc if h]
        websites_raw = body.get("website") or []
        if isinstance(websites_raw, str):
            websites_raw = websites_raw.split()
        websites = [w for w in websites_raw if w]

        extra_payload = {
            k: v
            for k, v in {
                "legalName": body.get("legal_name"),
                "industry": body.get("industry"),
                "country": body.get("country"),
                "registrationNumber": body.get("registration_number"),
                "contactEmail": body.get("contact_email"),
                "contactUrl": body.get("contact_url"),
                "description": body.get("description"),
            }.items()
            if v
        } or None

        import secrets as _secrets

        passphrase = _secrets.token_urlsafe(32)
        ti = TokenIdentity(
            policy_id=None,
            collection_name=company,
            asset_name=None,
            social_accounts=social,
            website=websites,
            rwa_details=None,
            extra_payload=extra_payload,
        )
        manager = PrismDIDManager(ti)
        did_doc = manager.create_did_document()
        priv_hex = manager.export_privkey_hex()
        enc_priv = encrypt_with_passphrase(passphrase, bytes.fromhex(priv_hex))

        # Schema-validate before persisting
        try:
            schema = json.load(open("token_identity/schemas/did_document.schema.json"))
            jsonschema_validate(did_doc, schema)
        except Exception as e:
            return _error(f"DID validation failed: {e}", status=500)

        twitter_str = " ".join(tw) if tw else ""
        discord_str = " ".join(dc) if dc else ""
        website_str = " ".join(websites)

        with session_scope(Session) as s:
            rec = DidRecord(
                user_id=g.api_user["id"],
                company=company,
                website=website_str,
                twitter=twitter_str,
                discord=discord_str,
                policy_id="",
                asset_name=None,
                did_id=did_doc["id"],
                did_doc=json.dumps(did_doc),
                project_privkey_encrypted=enc_priv,
                did_pubkey_jwk=json.dumps(did_doc["verificationMethod"][0]["publicKeyJwk"]),
                kyc_status="draft",
            )
            s.add(rec)
            s.flush()
            did_pk = rec.id
            s.add(AuditLog(user_id=g.api_user["id"], action="api_create_did", target=did_doc["id"], message=company))

        return (
            jsonify(
                {
                    "id": did_pk,
                    "did": did_doc["id"],
                    "didDocument": did_doc,
                    "kycStatus": "draft",
                    "privkey_hex": priv_hex,
                    "passphrase": passphrase,
                    "warning": "Save privkey_hex and passphrase now — they are not retrievable later.",
                }
            ),
            201,
        )

    @app.get("/api/v1/dids")
    @require_token
    def api_v1_did_list():
        with session_scope(Session) as s:
            rows = s.scalars(
                select(DidRecord).where(DidRecord.user_id == g.api_user["id"]).order_by(DidRecord.id.desc())
            ).all()
            return jsonify([_serialize_did(r) for r in rows])

    @app.get("/api/v1/dids/<int:did_id>")
    @require_token
    def api_v1_did_get(did_id: int):
        with session_scope(Session) as s:
            rec = s.get(DidRecord, did_id)
            if not rec:
                return _error("not found", status=404)
            if rec.user_id != g.api_user["id"] and not g.api_user["is_admin"]:
                return _error("forbidden", status=403)
            atts = s.scalars(select(Attestation).where(Attestation.did_record_id == rec.id)).all()
            creds = s.scalars(select(Credential).where(Credential.did_record_id == rec.id)).all()
            return jsonify(
                {
                    **_serialize_did(rec),
                    "didDocument": json.loads(rec.did_doc),
                    "attestations": [json.loads(a.attestation) for a in atts],
                    "credentials": [_serialize_cred(c) for c in creds],
                }
            )

    # -------- credentials --------

    @app.post("/api/v1/dids/<int:did_id>/credentials")
    @require_token
    def api_v1_vc_issue(did_id: int):
        body = _json_body()
        label = (body.get("label") or "").strip()
        if not label:
            return _error("`label` is required")

        with session_scope(Session) as s:
            rec = s.get(DidRecord, did_id)
            if not rec:
                return _error("DID not found", status=404)
            if rec.user_id != g.api_user["id"] and not g.api_user["is_admin"]:
                return _error("forbidden", status=403)
            priv = _resolve_privkey(rec, body)
            if not priv:
                return _error("need `privkey_hex` or `passphrase` to sign the credential", status=400)

        policy_id = body.get("policy_id") or None
        asset_name = body.get("asset_name") or None
        rwa = body.get("rwa_details") or None

        ti = TokenIdentity(
            policy_id=None,
            collection_name=rec.company,
            asset_name=None,
            social_accounts={},
            website=[],
        )
        manager = PrismDIDManager(ti, privkey_hex=priv.hex())
        base = _base_url()

        with session_scope(Session) as s:
            new_cred = Credential(did_record_id=did_id, label=label, vc_json="{}")
            s.add(new_cred)
            s.flush()
            cred_id = new_cred.id
            vc_id = f"{base}/api/credentials/{cred_id}"
            status_id = f"{base}/api/credentials/{cred_id}/status"
            vc = manager.create_company_vc(
                rec.did_id,
                policy_id=policy_id,
                asset_name=asset_name,
                rwa_details=rwa,
                label=label,
                extra={
                    "id": vc_id,
                    "credentialStatus": {"id": status_id, "type": "SimpleStatus"},
                    "issuer": {"id": rec.did_id, "url": f"{base}/api/dids/{did_id}/public"},
                },
            )
            new_cred.vc_json = json.dumps(vc)
            s.add(AuditLog(user_id=g.api_user["id"], action="api_create_vc", target=rec.did_id, message=label))
            return jsonify({"id": cred_id, "vc": vc}), 201

    @app.get("/api/v1/dids/<int:did_id>/credentials")
    @require_token
    def api_v1_vc_list(did_id: int):
        with session_scope(Session) as s:
            rec = s.get(DidRecord, did_id)
            if not rec:
                return _error("DID not found", status=404)
            if rec.user_id != g.api_user["id"] and not g.api_user["is_admin"]:
                return _error("forbidden", status=403)
            creds = s.scalars(
                select(Credential).where(Credential.did_record_id == rec.id).order_by(Credential.id.desc())
            ).all()
            return jsonify([_serialize_cred(c) for c in creds])

    @app.get("/api/v1/credentials/<int:cred_id>")
    @require_token
    def api_v1_vc_get(cred_id: int):
        with session_scope(Session) as s:
            cred = s.get(Credential, cred_id)
            if not cred:
                return _error("not found", status=404)
            rec = s.get(DidRecord, cred.did_record_id)
            if rec.user_id != g.api_user["id"] and not g.api_user["is_admin"]:
                return _error("forbidden", status=403)
            return jsonify(
                {
                    **_serialize_cred(cred),
                    "vc": json.loads(cred.vc_json),
                }
            )

    @app.post("/api/v1/credentials/<int:cred_id>/revoke")
    @require_token
    def api_v1_vc_revoke(cred_id: int):
        reason = (_json_body().get("reason") or "").strip()
        with session_scope(Session) as s:
            cred = s.get(Credential, cred_id)
            if not cred:
                return _error("not found", status=404)
            rec = s.get(DidRecord, cred.did_record_id)
            if rec.user_id != g.api_user["id"] and not g.api_user["is_admin"]:
                return _error("forbidden", status=403)
            cred.status = "revoked"
            cred.revoked_reason = reason
            cred.revoked_at = datetime.utcnow()
            s.add(AuditLog(user_id=g.api_user["id"], action="api_revoke_vc", target=rec.did_id, message=f"cred:{cred_id} {reason}"))
            return jsonify(_serialize_cred(cred))

    @app.post("/api/v1/credentials/<int:cred_id>/metadata")
    @require_token
    def api_v1_vc_metadata(cred_id: int):
        body = _json_body()
        with session_scope(Session) as s:
            cred = s.get(Credential, cred_id)
            if not cred:
                return _error("not found", status=404)
            rec = s.get(DidRecord, cred.did_record_id)
            if rec.user_id != g.api_user["id"] and not g.api_user["is_admin"]:
                return _error("forbidden", status=403)
            if cred.status == "revoked":
                return _error("credential is revoked", status=409)
            priv = _resolve_privkey(rec, body)
            if not priv:
                return _error("need `privkey_hex` or `passphrase` to sign metadata", status=400)
            vc = json.loads(cred.vc_json)
            did_id = rec.id
            did_record_id = rec.did_id
            company = rec.company

        policy_id = (vc.get("credentialSubject", {}) or {}).get("policyID")
        if not policy_id:
            return _error("credential is missing policy_id; cannot build 725 metadata", status=422)

        description = (body.get("description") or "").strip()
        author = (body.get("author_name") or "").strip()
        collection_override = (body.get("collection_name") or "").strip()
        did_name = description or "Token-Identity"
        vc_name = description or "Verification-Credential"
        if author:
            did_name = f"{did_name} — {author}"
            vc_name = f"{vc_name} — {author}"

        ti = TokenIdentity(
            policy_id=None,
            collection_name=company,
            asset_name=None,
            social_accounts={},
            website=[],
        )
        manager = PrismDIDManager(ti, privkey_hex=priv.hex())
        base = _base_url()
        vc_url = f"{base}/api/credentials/{cred_id}"
        try:
            md = manager.create_token_metadata(
                did_record_id,
                policy_id=policy_id,
                collection=collection_override or company,
                vc_url=vc_url,
                did_name=did_name,
                vc_name=vc_name,
            )
            schema = json.load(open("token_identity/schemas/token_metadata.schema.json"))
            jsonschema_validate(md, schema)
        except Exception as e:
            return _error(f"metadata generation failed: {e}", status=500)

        meta_dir = os.path.join(app.config["UPLOAD_FOLDER"], "metadata", f"cred_{cred_id}")
        os.makedirs(meta_dir, exist_ok=True)
        fname = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ") + ".json"
        with open(os.path.join(meta_dir, fname), "w", encoding="utf-8") as f:
            json.dump(md, f, indent=2)

        with session_scope(Session) as s:
            s.add(AuditLog(user_id=g.api_user["id"], action="api_create_metadata", target=did_record_id, message=f"cred:{cred_id}"))

        return jsonify({"metadata": md, "savedFilename": fname, "downloadUrl": f"{base}/did/{did_id}/credentials/{cred_id}/metadata/download?file={fname}"})
