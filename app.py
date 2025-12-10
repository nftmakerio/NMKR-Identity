from __future__ import annotations

import json
from typing import Dict, List, Any

import os
from flask import Flask, render_template, request, redirect, url_for, flash, send_file, jsonify, session
from flask_login import (
    LoginManager,
    login_user,
    logout_user,
    current_user,
    login_required,
    UserMixin,
)
from werkzeug.security import generate_password_hash, check_password_hash

from sqlalchemy import select

from webapp.db import init_engine, make_session_factory, Base, session_scope
from webapp.models import User, DidRecord, Attestation, Document, AuditLog, EmailToken, Credential
from webapp.forms import RegisterForm, LoginForm, DIDCreateForm, ApproveForm, ForgotPasswordForm, ResetPasswordForm, UploadDocForm, CreateCredentialForm
from webapp.crypto_utils import encrypt_with_passphrase, decrypt_with_passphrase
from werkzeug.utils import secure_filename
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from jsonschema import validate as jsonschema_validate
import hashlib
import zipfile
from io import BytesIO
import base64
from ecdsa import VerifyingKey, SECP256k1

from token_identity.models import TokenIdentity
from dotenv import load_dotenv
from token_identity.prism_did import PrismDIDManager


from token_identity.attestation import VerifierKey, create_verifier_attestation, create_verifier_vc
from token_identity.crypto import b64url_decode, verify_sig_secp256k1


class UserAdapter(UserMixin):
    def __init__(self, user_id: int, is_admin: bool):
        self._id = str(user_id)
        self._is_admin = bool(is_admin)

    def get_id(self):  # type: ignore[override]
        return self._id

    @property
    def is_admin(self) -> bool:
        return self._is_admin


def create_app() -> Flask:
    # Load local .env if present
    try:
        load_dotenv()
    except Exception:
        pass
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-change-me")
    app.config["UPLOAD_FOLDER"] = os.environ.get("UPLOAD_FOLDER", "uploads")
    # Optional: if BASE_URL is set (e.g., in production), we use it for link generation.
    # Otherwise, routes fall back to request.host_url at runtime for dynamic hosts.
    app.config["BASE_URL"] = (os.environ.get("BASE_URL") or "").rstrip("/")
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
    app.config.update(
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "0") == "1",
        MAX_CONTENT_LENGTH=int(os.environ.get("MAX_UPLOAD_MB", "25")) * 1024 * 1024,
    )
    app.config.setdefault("ALLOWED_EXTENSIONS", {"pdf", "png", "jpg", "jpeg", "webp"})

    # Database setup
    engine = init_engine(os.environ.get("DATABASE_URL", "sqlite:///app.db"))
    # Dev schema guard: if SQLite and schema out of date, rebuild
    try:
        from sqlalchemy import inspect
        insp = inspect(engine)
        # If did_records exists but missing new columns, drop and recreate (dev only)
        if insp.has_table("did_records"):
            cols = {c['name'] for c in insp.get_columns("did_records")}
            needed = {"project_privkey_encrypted", "did_pubkey_jwk", "kyc_notes", "kyc_decision_at"}
            if not needed.issubset(cols):
                # Danger: rebuild in dev
                Base.metadata.drop_all(engine)
        if insp.has_table("users"):
            ucols = {c['name'] for c in insp.get_columns("users")}
            if not {"email_verified", "api_token_hash"}.issubset(ucols):
                Base.metadata.drop_all(engine)
        if insp.has_table("credentials"):
            ccols = {c['name'] for c in insp.get_columns("credentials")}
            if not {"status", "revoked_reason", "revoked_at"}.issubset(ccols):
                Base.metadata.drop_all(engine)
    except Exception:
        pass
    Base.metadata.create_all(engine)
    Session = make_session_factory(engine)

    # Auth setup
    login_manager = LoginManager()
    login_manager.login_view = "login"
    login_manager.init_app(app)
    limiter = Limiter(get_remote_address, app=app, default_limits=["200 per hour"])  # global limit

    # Expose csrf_token() helper to templates for manual forms
    try:
        from flask_wtf.csrf import generate_csrf
        app.jinja_env.globals['csrf_token'] = generate_csrf
    except Exception:
        pass

    # 413 handler: file too large
    @app.errorhandler(413)
    def request_entity_too_large(_):
        max_mb = int(os.environ.get("MAX_UPLOAD_MB", "25"))
        flash(f"File too large. Maximum size is {max_mb} MB.", "error")
        return redirect(request.referrer or url_for("dashboard")), 413

    @login_manager.user_loader
    def load_user(user_id: str):  # type: ignore[override]
        with session_scope(Session) as s:
            u = s.get(User, int(user_id))
            return UserAdapter(u.id, bool(u.is_admin)) if u else None

    # Verifier key (admin signer) setup
    verifier_priv = os.environ.get("VERIFIER_PRIVKEY_HEX")
    app.config["VERIFIER"] = VerifierKey(privkey_hex=verifier_priv, name="PlatformVerifier")

    @app.get("/")
    def index():
        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))
        return render_template("index.html", landing=True)

    @app.get("/register")
    def register_page():
        form = RegisterForm()
        return render_template("register.html", form=form)

    # Bootstrap default admin
    with session_scope(Session) as s:
        admin_email = os.environ.get("ADMIN_EMAIL", "patrick@nmkr.io").lower()
        admin_pass = os.environ.get("ADMIN_PASSWORD", "admin")
        existing = s.scalar(select(User).where(User.email == admin_email))
        if not existing:
            u = User(email=admin_email, password_hash=generate_password_hash(admin_pass), is_admin=1, email_verified=1)
            s.add(u)
        else:
            # Ensure admin privileges and set the password as requested
            existing.is_admin = 1
            existing.password_hash = generate_password_hash(admin_pass)
            existing.email_verified = 1

    # Backfill existing credentials with vc.id and credentialStatus using BASE_URL
    def _backfill_vc_urls() -> int:
        base = app.config.get("BASE_URL", "").rstrip("/")
        updated = 0
        if not base:
            return 0
        with session_scope(Session) as s:
            creds = s.scalars(select(Credential)).all()
            for c in creds:
                try:
                    obj = json.loads(c.vc_json)
                except Exception:
                    continue
                # Do not mutate existing signed VCs; only compute would-be values
                if isinstance(obj, dict) and obj.get("proof"):
                    continue
                dirty = False
                desired_id = f"{base}/api/credentials/{c.id}"
                desired_status = f"{base}/api/credentials/{c.id}/status"
                if not obj.get("id") or not str(obj.get("id")).startswith(base):
                    obj["id"] = desired_id
                    dirty = True
                cs = obj.get("credentialStatus") if isinstance(obj.get("credentialStatus"), dict) else {}
                cs_id = cs.get("id") if isinstance(cs, dict) else None
                if not cs_id or not str(cs_id).startswith(base):
                    obj["credentialStatus"] = {"id": desired_status, "type": "SimpleStatus"}
                    dirty = True
                if dirty:
                    c.vc_json = json.dumps(obj)
                    updated += 1
        return updated

    try:
        _ = _backfill_vc_urls()
    except Exception:
        pass

    @app.post("/register")
    @limiter.limit("10 per hour")
    def register():
        form = RegisterForm()
        if not form.validate_on_submit():
            flash("Invalid input", "error")
            return redirect(url_for("register_page"))
        email = form.email.data.strip().lower()
        password = form.password.data
        with session_scope(Session) as s:
            exists = s.scalar(select(User).where(User.email == email))
            if exists:
                flash("Email already registered", "error")
                return redirect(url_for("register_page"))
            u = User(email=email, password_hash=generate_password_hash(password), is_admin=0)
            s.add(u)
            s.flush()
            # Dev: emit verify link
            import secrets
            tok = secrets.token_urlsafe(24)
            s.add(EmailToken(user_id=u.id, token=tok, purpose="verify"))
            # Do not flash here; the persistent unverified banner will inform the user
            # Log the verify link for developers (no exposure in UI)
            try:
                base = app.config.get("BASE_URL") or request.host_url.rstrip("/")
                link = f"{base}/verify?token={tok}"
                sent = _send_email(email, "Verify your email", f"Welcome! Click to verify: {link}")
                app.logger.info("Register verify link for %s: %s (sent=%s)", email, link, bool(sent))
                if app.debug:
                    flash(f"Dev verify link: {link}", "info")
            except Exception as e:
                try:
                    app.logger.info("Register verify: error %s", e)
                except Exception:
                    pass
            login_user(UserAdapter(u.id, bool(u.is_admin)))
        return redirect(url_for("dashboard"))

    @app.get("/login")
    def login_page():
        form = LoginForm()
        return render_template("login.html", form=form)

    @app.post("/login")
    @limiter.limit("20 per hour")
    def login():
        form = LoginForm()
        if not form.validate_on_submit():
            flash("Invalid input", "error")
            return redirect(url_for("login_page"))
        email = form.email.data.strip().lower()
        password = form.password.data
        with session_scope(Session) as s:
            u = s.scalar(select(User).where(User.email == email))
            if not u or not check_password_hash(u.password_hash, password):
                flash("Invalid credentials", "error")
                return redirect(url_for("login_page"))
            login_user(UserAdapter(u.id, bool(u.is_admin)))
        return redirect(url_for("dashboard"))

    @app.get("/verify")
    def verify_email():
        token = request.args.get("token", "")
        if not token:
            return "Missing token", 400
        with session_scope(Session) as s:
            et = s.scalar(select(EmailToken).where(EmailToken.token == token, EmailToken.purpose == "verify"))
            if not et:
                return "Invalid token", 400
            u = s.get(User, et.user_id)
            if not u:
                return "Invalid user", 400
            u.email_verified = 1
        flash("Email verified. You can now log in.", "info")
        return redirect(url_for("login_page"))

    @app.get("/forgot")
    def forgot_page():
        form = ForgotPasswordForm()
        return render_template("forgot.html", form=form)

    @app.post("/forgot")
    def forgot():
        form = ForgotPasswordForm()
        if not form.validate_on_submit():
            flash("Invalid input", "error")
            return redirect(url_for("forgot_page"))
        email = form.email.data.strip().lower()
        with session_scope(Session) as s:
            u = s.scalar(select(User).where(User.email == email))
            if not u:
                flash("If the email exists, a reset link was generated.", "info")
                return redirect(url_for("login_page"))
            import secrets
            tok = secrets.token_urlsafe(24)
            s.add(EmailToken(user_id=u.id, token=tok, purpose="reset"))
            flash(f"Password reset link: /reset?token={tok}", "info")
        return redirect(url_for("login_page"))

    @app.get("/reset")
    def reset_page():
        token = request.args.get("token", "")
        form = ResetPasswordForm(token=token)
        return render_template("reset.html", form=form)

    @app.post("/reset")
    def reset():
        form = ResetPasswordForm()
        if not form.validate_on_submit():
            flash("Invalid input", "error")
            return redirect(url_for("reset_page"))
        token = form.token.data
        new_password = form.new_password.data
        with session_scope(Session) as s:
            et = s.scalar(select(EmailToken).where(EmailToken.token == token, EmailToken.purpose == "reset"))
            if not et:
                flash("Invalid token", "error")
                return redirect(url_for("login_page"))
            u = s.get(User, et.user_id)
            if not u:
                flash("Invalid user", "error")
                return redirect(url_for("login_page"))
            u.password_hash = generate_password_hash(new_password)
        flash("Password updated.", "info")
        return redirect(url_for("login_page"))

    @app.get("/logout")
    @login_required
    def logout():
        logout_user()
        return redirect(url_for("index"))

    @app.get("/dashboard")
    @login_required
    def dashboard():
        from sqlalchemy import func
        user_id = int(current_user.get_id())
        with session_scope(Session) as s:
            recs = s.scalars(select(DidRecord).where(DidRecord.user_id == user_id)).all()
            rows = []
            for r in recs:
                att_count = s.scalar(select(func.count(Attestation.id)).where(Attestation.did_record_id == r.id)) or 0
                rows.append({
                    "company": r.company,
                    "did_id": r.did_id,
                    "id": r.id,
                    "kyc_status": r.kyc_status,
                    "attestation_count": int(att_count),
                })
            # Collect all credentials across user's DIDs
            from sqlalchemy import join
            q = select(Credential, DidRecord).join(DidRecord, Credential.did_record_id == DidRecord.id).where(DidRecord.user_id == user_id)
            cred_rows = s.execute(q).all()
            creds = [{
                "id": c.id,
                "label": c.label,
                "status": c.status,
                "did_id": d.id,
                "company": d.company,
            } for (c, d) in cred_rows]
        form = DIDCreateForm()
        # Decide the next step URL per did
        for r in rows:
            if r["kyc_status"] in ("draft", "pending"):
                r["continue_url"] = url_for("wizard_kyc", did_id=r.get("id", 0))
            elif r["kyc_status"] == "submitted":
                r["continue_url"] = url_for("wizard_review", did_id=r.get("id", 0))
            elif r["kyc_status"] in ("approved", "rejected"):
                # Go directly to DID detail (credentials) once approved/rejected
                r["continue_url"] = url_for("did_detail", did_id=r.get("id", 0)) + "#credentials"
            else:
                r["continue_url"] = url_for("did_detail", did_id=r.get("id", 0))
        return render_template("dashboard.html", dids=rows, creds=creds, form=form)

    @app.post("/submit")
    @login_required
    def submit():
        form = DIDCreateForm()
        if not form.validate_on_submit():
            flash("Please fill required fields", "error")
            return redirect(url_for("dashboard"))
        company = form.company.data.strip()
        website = form.website.data.strip() if form.website.data else ""
        twitter = form.twitter.data.strip() if form.twitter.data else ""
        discord = form.discord.data.strip() if form.discord.data else ""
        # Optional company details
        legal_name = (form.legal_name.data or "").strip()
        industry = (form.industry.data or "").strip()
        country = (form.country.data or "").strip()
        registration_number = (form.registration_number.data or "").strip()
        contact_email = (form.contact_email.data or "").strip()
        contact_url = (form.contact_url.data or "").strip()
        description = (form.description.data or "").strip()
        # Company-level DID only; no policy/asset/RWA at this stage
        # Generate a strong passphrase server-side; user will download it
        import secrets as _secrets
        key_passphrase = _secrets.token_urlsafe(32)

        social: Dict[str, List[str]] = {}
        if twitter:
            social["twitter"] = [h for h in twitter.split() if h]
        if discord:
            social["discord"] = [h for h in discord.split() if h]
        websites = [w for w in website.split() if w]

        rwa_details: Dict[str, Any] | None = None

        extra_payload: Dict[str, Any] = {}
        if legal_name:
            extra_payload["legalName"] = legal_name
        if industry:
            extra_payload["industry"] = industry
        if country:
            extra_payload["country"] = country
        if registration_number:
            extra_payload["registrationNumber"] = registration_number
        if contact_email:
            extra_payload["contactEmail"] = contact_email
        if contact_url:
            extra_payload["contactUrl"] = contact_url
        if description:
            extra_payload["description"] = description

        ti = TokenIdentity(
            policy_id=None,
            collection_name=company,
            asset_name=None,
            social_accounts=social,
            website=websites,
            rwa_details=None,
            extra_payload=extra_payload or None,
        )

        manager = PrismDIDManager(ti)
        did_doc = manager.create_did_document()
        did = did_doc["id"]
        priv_hex = manager.export_privkey_hex()
        enc_priv = encrypt_with_passphrase(key_passphrase, bytes.fromhex(priv_hex))

        # Validate DID
        try:
            schema = json.load(open("token_identity/schemas/did_document.schema.json"))
            jsonschema_validate(did_doc, schema)
        except Exception as e:
            flash(f"DID validation failed: {e}", "error")
            return redirect(url_for("dashboard"))

        with session_scope(Session) as s:
            rec = DidRecord(
                user_id=int(current_user.get_id()),
                company=company,
                website=website,
                twitter=twitter,
                discord=discord,
                policy_id="",
                asset_name=None,
                did_id=did,
                did_doc=json.dumps(did_doc),
                project_privkey_encrypted=enc_priv,
                did_pubkey_jwk=json.dumps(did_doc["verificationMethod"][0]["publicKeyJwk"]),
                kyc_status="draft",
            )
            s.add(rec)
            s.add(AuditLog(user_id=int(current_user.get_id()), action="create_did", target=did, message=f"Company {company}"))
        # Redirect into wizard step 2 (Save Key)
        with session_scope(Session) as s:
            rec = s.scalar(select(DidRecord).where(DidRecord.did_id == did))
            did_pk = rec.id if rec else 0
        # Store the generated key in the user session for a one-time download
        session[f"key_{did_pk}"] = key_passphrase
        return redirect(url_for("wizard_key", did_id=did_pk))

    # Admin panel
    @app.get("/admin")
    @login_required
    def admin_panel():
        # Only admins
        user_id = int(current_user.get_id())
        with session_scope(Session) as s:
            u = s.get(User, user_id)
            if not u or not u.is_admin:
                return "Forbidden", 403
            from sqlalchemy import func
            recs = s.scalars(select(DidRecord)).all()
            rows = []
            for r in recs:
                att_count = s.scalar(select(func.count(Attestation.id)).where(Attestation.did_record_id == r.id)) or 0
                owner = s.get(User, r.user_id)
                rows.append({
                    "id": r.id,
                    "company": r.company,
                    "did_id": r.did_id,
                    "kyc_status": r.kyc_status,
                    "attestation_count": int(att_count),
                    "owner_email": owner.email if owner else "",
                    "owner_verified": bool(owner.email_verified) if owner else False,
                })
        verifier: VerifierKey = app.config["VERIFIER"]
        return render_template("admin.html", dids=rows, verifier_did=verifier.did)

    @app.post("/admin/backfill-vc-urls")
    @login_required
    def admin_backfill_vc_urls():
        with session_scope(Session) as s:
            u = s.get(User, int(current_user.get_id()))
            if not u or not u.is_admin:
                return "Forbidden", 403
        updated = 0
        try:
            updated = _backfill_vc_urls()
        except Exception:
            updated = 0
        flash(f"Backfilled {updated} credential(s).", "info")
        return redirect(url_for("admin_panel"))

    @app.get("/admin/did/<int:did_id>")
    @login_required
    def admin_did(did_id: int):
        with session_scope(Session) as s:
            u = s.get(User, int(current_user.get_id()))
            if not u or not u.is_admin:
                return "Forbidden", 403
            rec = s.get(DidRecord, did_id)
            if not rec:
                return "Not found", 404
            owner = s.get(User, rec.user_id)
            docs = s.scalars(select(Document).where(Document.did_record_id == rec.id)).all()
        return render_template("admin_did.html", rec=rec, owner=owner, documents=docs)

    @app.get("/admin/did/<int:did_id>/docs/<int:doc_id>")
    @login_required
    def admin_doc_serve(did_id: int, doc_id: int):
        with session_scope(Session) as s:
            u = s.get(User, int(current_user.get_id()))
            if not u or not u.is_admin:
                return "Forbidden", 403
            rec = s.get(DidRecord, did_id)
            doc = s.get(Document, doc_id)
            if not rec or not doc or doc.did_record_id != rec.id:
                return "Not found", 404
            path = doc.stored_path
        ap = os.path.abspath(path)
        root = os.path.abspath(app.config["UPLOAD_FOLDER"])
        if not ap.startswith(root):
            return "Forbidden", 403
        try:
            return send_file(ap)
        except Exception:
            return "File error", 404

    @app.get("/admin/did/<int:did_id>/docs.zip")
    @login_required
    def admin_docs_zip(did_id: int):
        with session_scope(Session) as s:
            u = s.get(User, int(current_user.get_id()))
            if not u or not u.is_admin:
                return "Forbidden", 403
            rec = s.get(DidRecord, did_id)
            if not rec:
                return "Not found", 404
            docs = s.scalars(select(Document).where(Document.did_record_id == rec.id)).all()
        buf = BytesIO()
        with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
            for d in docs:
                try:
                    z.write(d.stored_path, arcname=d.filename)
                except Exception:
                    pass
        buf.seek(0)
        return send_file(buf, mimetype='application/zip', as_attachment=True, download_name=f"kyc_docs_{did_id}.zip")

    @app.post("/admin/approve/<int:did_id>")
    @login_required
    def admin_approve(did_id: int):
        notes = request.form.get("notes", "")
        with session_scope(Session) as s:
            u = s.get(User, int(current_user.get_id()))
            if not u or not u.is_admin:
                return "Forbidden", 403
            rec = s.get(DidRecord, did_id)
            if not rec:
                return "Not found", 404
            owner = s.get(User, rec.user_id)
            from datetime import datetime as _dt
            rec.kyc_status = "approved"
            rec.kyc_notes = notes
            rec.kyc_decision_at = _dt.utcnow()
            verifier: VerifierKey = app.config["VERIFIER"]
            att = create_verifier_attestation(verifier, rec.did_id, rec.policy_id or "")
            att_row = Attestation(
                did_record_id=rec.id,
                attester_did=verifier.did,
                attestation=json.dumps(att),
            )
            s.add(att_row)
            vc = create_verifier_vc(verifier, rec.did_id, rec.policy_id or "")
            s.add(Attestation(did_record_id=rec.id, attester_did=verifier.did, attestation=json.dumps(vc)))
            s.add(AuditLog(user_id=u.id, action="approve", target=rec.did_id, message=notes))
        return redirect(url_for("admin_panel"))

    @app.get("/did/<int:did_id>")
    @login_required
    def did_detail(did_id: int):
        with session_scope(Session) as s:
            rec = s.get(DidRecord, did_id)
            if not rec:
                return "Not found", 404
            if int(current_user.get_id()) != rec.user_id and not current_user.is_admin:
                return "Forbidden", 403
            atts = s.scalars(select(Attestation).where(Attestation.did_record_id == rec.id)).all()
            docs = s.scalars(select(Document).where(Document.did_record_id == rec.id)).all()
        has_key = bool(session.get(f"key_{did_id}"))
        # Filters for credentials (status, q)
        status = request.args.get("status", "")
        q = request.args.get("q", "").strip()
        simple = request.args.get("simple", "0") == "1"
        with session_scope(Session) as s:
            stmt = select(Credential).where(Credential.did_record_id == rec.id)
            if status in ("active", "revoked"):
                from sqlalchemy import literal
                stmt = stmt.where(Credential.status == status)
            if q:
                stmt = stmt.where(Credential.label.ilike(f"%{q}%"))
            creds = s.scalars(stmt).all()
        # Pretty-print JSON blobs for readability in the UI
        try:
            did_doc_pretty = json.dumps(json.loads(rec.did_doc), indent=2)
        except Exception:
            did_doc_pretty = rec.did_doc
        try:
            att_pretty = [json.dumps(json.loads(a.attestation), indent=2) for a in atts]
        except Exception:
            att_pretty = [getattr(a, 'attestation', '') for a in atts]
        return render_template(
            "did_detail.html",
            rec=rec,
            attestations=atts,
            attestations_pretty=att_pretty,
            documents=docs,
            has_key=has_key,
            credentials=creds,
            filter_status=status,
            filter_q=q,
            simple=simple,
            did_doc_pretty=did_doc_pretty,
        )

    @app.get("/did/<int:did_id>/download")
    @login_required
    def did_download(did_id: int):
        with session_scope(Session) as s:
            rec = s.get(DidRecord, did_id)
            if not rec:
                return "Not found", 404
            if int(current_user.get_id()) != rec.user_id and not current_user.is_admin:
                return "Forbidden", 403
        from io import BytesIO
        buf = BytesIO()
        buf.write(rec.did_doc.encode())
        buf.seek(0)
        return send_file(buf, mimetype="application/json", as_attachment=True, download_name=f"did_{did_id}.json")

    @app.post("/did/<int:did_id>/generate-metadata")
    @login_required
    def did_generate_metadata(did_id: int):
        passphrase = request.form.get("key_passphrase", "")
        key_file = request.files.get("key_file")
        if key_file and key_file.filename:
            try:
                data = key_file.read().decode().strip()
                passphrase = data
            except Exception:
                flash("Invalid key file", "error")
                return redirect(url_for("did_detail", did_id=did_id))
        if not passphrase:
            flash("Passphrase required to decrypt key", "error")
            return redirect(url_for("did_detail", did_id=did_id))
        with session_scope(Session) as s:
            rec = s.get(DidRecord, did_id)
            if not rec:
                return "Not found", 404
            if int(current_user.get_id()) != rec.user_id and not current_user.is_admin:
                return "Forbidden", 403
            try:
                priv = decrypt_with_passphrase(passphrase, rec.project_privkey_encrypted)
            except Exception:
                flash("Invalid passphrase", "error")
                return redirect(url_for("did_detail", did_id=did_id))
        ti = TokenIdentity(policy_id=None, collection_name=rec.company, asset_name=None, social_accounts={}, website=[])
        mgr = PrismDIDManager(ti, privkey_hex=priv.hex())
        md = mgr.create_token_metadata(rec.did_id, policy_id=(request.form.get("policy_id") or None), collection=rec.company, vc_url=None)
        try:
            schema = json.load(open("token_identity/schemas/token_metadata.schema.json"))
            jsonschema_validate(md, schema)
        except Exception as e:
            flash(f"Metadata validation failed: {e}", "error")
            return redirect(url_for("did_detail", did_id=did_id))
        buf = BytesIO()
        buf.write(json.dumps(md, indent=2).encode())
        buf.seek(0)
        return send_file(buf, mimetype="application/json", as_attachment=True, download_name=f"metadata_{did_id}.json")

    # Create a new Verified Credential (per asset/project) under a company DID
    @app.post("/did/<int:did_id>/credentials/create")
    @login_required
    def credential_create(did_id: int):
        form = CreateCredentialForm()
        if not form.validate_on_submit():
            # Surface validation errors to the user
            if getattr(form, 'errors', None):
                problems = []
                for field, errs in form.errors.items():
                    for e in errs:
                        problems.append(f"{field}: {e}")
                if problems:
                    flash("; ".join(problems), "error")
                else:
                    flash("Invalid input", "error")
            else:
                flash("Invalid input", "error")
            return redirect(url_for("credential_new", did_id=did_id))
        with session_scope(Session) as s:
            rec = s.get(DidRecord, did_id)
            if not rec:
                return "Not found", 404
            if int(current_user.get_id()) != rec.user_id and not current_user.is_admin:
                return "Forbidden", 403
        passphrase = form.key_passphrase.data or ""
        key_file = request.files.get("key_file")
        if key_file and key_file.filename:
            try:
                passphrase = key_file.read().decode().strip()
            except Exception:
                flash("Invalid key file", "error")
                return redirect(url_for("credential_new", did_id=did_id))
        if not passphrase:
            flash("Key file or passphrase required", "error")
            return redirect(url_for("credential_new", did_id=did_id))
        with session_scope(Session) as s:
            rec = s.get(DidRecord, did_id)
            try:
                priv = decrypt_with_passphrase(passphrase, rec.project_privkey_encrypted)
            except Exception:
                flash("Invalid passphrase", "error")
                return redirect(url_for("credential_new", did_id=did_id))
        from token_identity.models import TokenIdentity as _TI
        ti = _TI(policy_id=None, collection_name=rec.company, asset_name=None, social_accounts={}, website=[])
        mgr = PrismDIDManager(ti, privkey_hex=priv.hex())
        rwa = None
        if (form.rwa_asset_type.data or form.rwa_jurisdiction.data or form.rwa_registration.data):
            rwa = {k: v for k, v in {
                "assetType": form.rwa_asset_type.data or None,
                "jurisdiction": form.rwa_jurisdiction.data or None,
                "registrationNumber": form.rwa_registration.data or None,
            }.items() if v}
        # Persist a row to get credential ID
        with session_scope(Session) as s:
            new_cred = Credential(did_record_id=did_id, label=form.label.data, vc_json="{}")
            s.add(new_cred)
            s.flush()  # assign ID
            base = app.config.get("BASE_URL") or request.host_url.rstrip("/")
            vc_id = f"{base}/api/credentials/{new_cred.id}"
            status_id = f"{base}/api/credentials/{new_cred.id}/status"
            # Create VC with extra fields included before signing
            vc = mgr.create_company_vc(
                rec.did_id,
                policy_id=(form.policy_id.data or None),
                asset_name=(form.asset_name.data or None),
                rwa_details=rwa,
                label=form.label.data,
                extra={
                    "id": vc_id,
                    "credentialStatus": {"id": status_id, "type": "SimpleStatus"},
                    "issuer": {"id": rec.did_id, "url": f"{base}/api/dids/{did_id}/public"},
                },
            )
            new_cred.vc_json = json.dumps(vc)
            s.add(AuditLog(user_id=int(current_user.get_id()), action="create_vc", target=rec.did_id, message=form.label.data))
        flash("Credential created.", "info")
        return redirect(url_for("credential_detail", did_id=did_id, cred_id=new_cred.id))

    @app.get("/did/<int:did_id>/credentials/new")
    @login_required
    def credential_new(did_id: int):
        with session_scope(Session) as s:
            rec = s.get(DidRecord, did_id)
            if not rec:
                return "Not found", 404
            if int(current_user.get_id()) != rec.user_id and not current_user.is_admin:
                return "Forbidden", 403
        form = CreateCredentialForm()
        return render_template("credential_create.html", rec=rec, form=form)

    # Download VC JSON
    @app.get("/did/<int:did_id>/credentials/<int:cred_id>/download")
    @login_required
    def credential_download(did_id: int, cred_id: int):
        with session_scope(Session) as s:
            rec = s.get(DidRecord, did_id)
            cred = s.get(Credential, cred_id)
            if not rec or not cred or cred.did_record_id != rec.id:
                return "Not found", 404
            if int(current_user.get_id()) != rec.user_id and not current_user.is_admin:
                return "Forbidden", 403
        from io import BytesIO
        buf = BytesIO()
        buf.write(json.dumps(json.loads(cred.vc_json), indent=2).encode())
        buf.seek(0)
        return send_file(buf, mimetype="application/json", as_attachment=True, download_name=f"vc_{cred_id}.json")

    # VC detail page (view, generate metadata, share)
    @app.get("/did/<int:did_id>/credentials/<int:cred_id>")
    @login_required
    def credential_detail(did_id: int, cred_id: int):
        with session_scope(Session) as s:
            rec = s.get(DidRecord, did_id)
            cred = s.get(Credential, cred_id)
            if not rec or not cred or cred.did_record_id != rec.id:
                return "Not found", 404
            if int(current_user.get_id()) != rec.user_id and not current_user.is_admin:
                return "Forbidden", 403
            vc = json.loads(cred.vc_json)
        public_url = url_for('api_credential_public', cred_id=cred_id, _external=True)
        # List saved metadata versions if present
        meta_dir = os.path.join(app.config["UPLOAD_FOLDER"], "metadata", f"cred_{cred_id}")
        md_list: list[dict] = []
        selected_name = request.args.get("md", "")
        selected_content = None
        try:
            if os.path.isdir(meta_dir):
                for name in os.listdir(meta_dir):
                    if name.endswith('.json'):
                        path = os.path.join(meta_dir, name)
                        try:
                            stat = os.stat(path)
                            md_list.append({"name": name, "mtime": stat.st_mtime})
                        except Exception:
                            pass
                md_list.sort(key=lambda x: x["mtime"], reverse=True)
                # Choose selected
                if not selected_name and md_list:
                    selected_name = md_list[0]["name"]
                if selected_name:
                    safe = os.path.normpath(os.path.join(meta_dir, selected_name))
                    if os.path.commonpath([safe, meta_dir]) == meta_dir and os.path.exists(safe):
                        with open(safe, "r", encoding="utf-8") as f:
                            selected_content = json.dumps(json.load(f), indent=2)
        except Exception:
            pass
        return render_template(
            "credential_detail.html",
            rec=rec,
            cred=cred,
            vc=vc,
            public_url=public_url,
            metadata_files=md_list,
            selected_metadata=selected_content,
            selected_metadata_name=selected_name,
        )

    # Human-readable verification: performs all steps a third party would do and reports results
    @app.get("/did/<int:did_id>/credentials/<int:cred_id>/verify")
    @login_required
    def credential_verify(did_id: int, cred_id: int):
        steps: list[dict[str, str]] = []
        with session_scope(Session) as s:
            rec = s.get(DidRecord, did_id)
            cred = s.get(Credential, cred_id)
            if not rec or not cred or cred.did_record_id != rec.id:
                return "Not found", 404
            if int(current_user.get_id()) != rec.user_id and not current_user.is_admin:
                return "Forbidden", 403
            atts = s.scalars(select(Attestation).where(Attestation.did_record_id == rec.id)).all()
        # Load VC and DID
        try:
            vc = json.loads(cred.vc_json)
            steps.append({"name": "Load VC", "status": "ok", "detail": "VC JSON parsed"})
        except Exception as e:
            steps.append({"name": "Load VC", "status": "fail", "detail": f"Invalid VC JSON: {e}"})
            return render_template("credential_verify.html", rec=rec, cred=cred, steps=steps)
        try:
            did_doc = json.loads(rec.did_doc)
        except Exception as e:
            steps.append({"name": "Load DID", "status": "fail", "detail": f"Invalid DID Document JSON: {e}"})
            return render_template("credential_verify.html", rec=rec, cred=cred, steps=steps)

        # Extract issuer DID from VC (string or object)
        issuer_did = vc.get("issuer")
        if isinstance(issuer_did, dict):
            issuer_did = issuer_did.get("id")
        if issuer_did == rec.did_id:
            steps.append({"name": "Issuer DID", "status": "ok", "detail": issuer_did})
        else:
            steps.append({"name": "Issuer DID", "status": "fail", "detail": f"Issuer {issuer_did} != expected {rec.did_id}"})

        # 1) Verify DID Document signature using its public JWK
        try:
            vm = did_doc.get("verificationMethod", [{}])[0]
            jwk = vm.get("publicKeyJwk", {})
            x = b64url_decode(jwk.get("x", ""))
            y = b64url_decode(jwk.get("y", ""))
            vk = VerifyingKey.from_string(x + y, curve=SECP256k1)
            did_msg = json.dumps(did_doc.get("payload", {}), sort_keys=True).encode()
            did_sig = b64url_decode(did_doc.get("proof", {}).get("signatureValue", ""))
            did_ok = verify_sig_secp256k1(vk, did_msg, did_sig)
            steps.append({"name": "Verify DID Document", "status": "ok" if did_ok else "fail", "detail": "Signature over payload"})
        except Exception as e:
            steps.append({"name": "Verify DID Document", "status": "fail", "detail": f"{e}"})

        # 2) Verify VC signature using DID's public key
        try:
            vc_copy = json.loads(json.dumps(vc))
            proof = vc_copy.pop("proof", {})
            vc_msg = json.dumps(vc_copy, sort_keys=True).encode()
            sig_b64 = proof.get("jws") or proof.get("signatureValue") or ""
            vc_sig = b64url_decode(sig_b64)
            vc_ok = verify_sig_secp256k1(vk, vc_msg, vc_sig)
            steps.append({"name": "Verify VC", "status": "ok" if vc_ok else "fail", "detail": "Signature matches DID key"})
        except Exception as e:
            steps.append({"name": "Verify VC", "status": "fail", "detail": f"{e}"})

        # 3) Verify platform attestation(s)
        try:
            v: VerifierKey = app.config.get("VERIFIER")  # type: ignore
            vvk = None
            try:
                vjwk = v.jwk()
                vx = b64url_decode(vjwk.get("x", ""))
                vy = b64url_decode(vjwk.get("y", ""))
                vvk = VerifyingKey.from_string(vx + vy, curve=SECP256k1)
            except Exception:
                vvk = None
            verified_any = False
            for arow in atts:
                try:
                    att = json.loads(arow.attestation)
                except Exception:
                    continue
                att_copy = json.loads(json.dumps(att))
                proof = att_copy.pop("proof", {})
                msg = json.dumps(att_copy, sort_keys=True).encode()
                sig_b64 = proof.get("jws") or proof.get("signatureValue") or ""
                sig = b64url_decode(sig_b64)
                # Prefer key embedded with attestation (verifierJwk) if present
                att_jwk = att_copy.get("verifierJwk") if isinstance(att_copy, dict) else None
                tried = False
                if isinstance(att_jwk, dict):
                    try:
                        ax = b64url_decode(att_jwk.get("x", ""))
                        ay = b64url_decode(att_jwk.get("y", ""))
                        avk = VerifyingKey.from_string(ax + ay, curve=SECP256k1)
                        if verify_sig_secp256k1(avk, msg, sig):
                            verified_any = True
                            tried = True
                    except Exception:
                        pass
                # Fallback to current platform verifier key
                if not tried and vvk is not None:
                    if verify_sig_secp256k1(vvk, msg, sig):
                        verified_any = True
            steps.append({"name": "Verify Platform Attestation", "status": "ok" if verified_any else "fail", "detail": "At least one attestation signature valid"})
        except Exception as e:
            steps.append({"name": "Verify Platform Attestation", "status": "fail", "detail": f"{e}"})

        # 4) Credential status
        steps.append({"name": "Credential Status", "status": "ok" if cred.status != 'revoked' else "fail", "detail": cred.status})

        return render_template("credential_verify.html", rec=rec, cred=cred, steps=steps, vc=vc)

    # Public QR for VC URL
    @app.get("/api/credentials/<int:cred_id>/qr.png")
    def api_credential_qr(cred_id: int):
        with session_scope(Session) as s:
            cred = s.get(Credential, cred_id)
            if not cred:
                return "Not found", 404
        try:
            import qrcode
            from io import BytesIO
            buf = BytesIO()
            url = url_for('api_credential_public', cred_id=cred_id, _external=True)
            img = qrcode.make(url)
            img.save(buf, format='PNG')
            buf.seek(0)
            return send_file(buf, mimetype='image/png')
        except Exception:
            return "QR error", 500

    @app.get("/did/<int:did_id>/download-key")
    @login_required
    def did_download_key(did_id: int):
        key = session.get(f"key_{did_id}")
        if not key:
            return "Not available", 404
        session.pop(f"key_{did_id}", None)
        from io import BytesIO
        buf = BytesIO()
        buf.write((key + "\n").encode())
        buf.seek(0)
        return send_file(buf, mimetype="text/plain", as_attachment=True, download_name=f"did_{did_id}_key.txt")

    # Confirm that user saved the generated key
    @app.post("/did/<int:did_id>/key-confirm")
    @login_required
    def key_confirm(did_id: int):
        session[f"key_confirmed_{did_id}"] = True
        flash("Thanks! Key saved confirmation recorded for this session.", "info")
        return redirect(request.referrer or url_for("did_detail", did_id=did_id))

    # Test decrypt: validate uploaded key file or passphrase can decrypt stored key
    @app.post("/did/<int:did_id>/key-test")
    @login_required
    def key_test(did_id: int):
        passphrase = request.form.get("key_passphrase", "")
        key_file = request.files.get("key_file")
        next_url = request.form.get("next") or request.args.get("next") or request.referrer or url_for("wizard_key", did_id=did_id)
        if key_file and key_file.filename:
            try:
                passphrase = key_file.read().decode().strip()
            except Exception:
                flash("Invalid key file", "error")
                return redirect(next_url)
        if not passphrase:
            flash("Provide a key file or passphrase to test", "error")
            return redirect(next_url)
        with session_scope(Session) as s:
            rec = s.get(DidRecord, did_id)
            if not rec:
                return "Not found", 404
            if int(current_user.get_id()) != rec.user_id and not current_user.is_admin:
                return "Forbidden", 403
            try:
                _ = decrypt_with_passphrase(passphrase, rec.project_privkey_encrypted)
            except Exception:
                flash("Key test failed: passphrase did not decrypt.", "error")
                return redirect(next_url)
        flash("Key test successful: decryption works.", "info")
        return redirect(next_url)

    @app.post("/did/<int:did_id>/upload")
    @login_required
    def did_upload(did_id: int):
        with session_scope(Session) as s:
            rec = s.get(DidRecord, did_id)
            if not rec:
                return "Not found", 404
            if int(current_user.get_id()) != rec.user_id and not current_user.is_admin:
                return "Forbidden", 403
        files = request.files.getlist("files") or []
        if not files:
            # Fallback for single legacy name
            single = request.files.get("file")
            if single and single.filename:
                files = [single]
        if not files:
            flash("No file selected", "error")
            return redirect(url_for("did_detail", did_id=did_id))
        saved = 0
        allowed = app.config["ALLOWED_EXTENSIONS"]
        os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
        import uuid
        for file in files:
            fname = secure_filename(file.filename)
            if not fname:
                continue
            ext = fname.rsplit('.', 1)[-1].lower() if '.' in fname else ''
            if ext not in allowed:
                flash(f"Unsupported file type .{ext} for {fname}. Allowed: {', '.join(sorted(allowed))}", "error")
                continue
            unique = f"{uuid.uuid4().hex}_{fname}"
            path = os.path.join(app.config["UPLOAD_FOLDER"], unique)
            file.save(path)
            with session_scope(Session) as s:
                s.add(Document(did_record_id=did_id, filename=fname, stored_path=path))
                s.add(AuditLog(user_id=int(current_user.get_id()), action="upload_doc", target=str(did_id), message=fname))
            saved += 1
        if saved:
            flash(f"Uploaded {saved} file(s)", "info")
        else:
            flash("No files were uploaded.", "error")
        next_url = request.args.get("next") or request.form.get("next")
        if next_url:
            return redirect(next_url)
        return redirect(url_for("did_detail", did_id=did_id))

    @app.get("/api/dids/<int:did_id>")
    @login_required
    def api_did(did_id: int):
        # Token-based auth support
        auth = request.headers.get("Authorization", "")
        user_from_token = None
        if auth.startswith("Bearer "):
            token = auth.split(" ", 1)[1]
            h = hashlib.sha256(token.encode()).hexdigest()
            with session_scope(Session) as s:
                user_from_token = s.scalar(select(User).where(User.api_token_hash == h))
        with session_scope(Session) as s:
            rec = s.get(DidRecord, did_id)
            if not rec:
                return jsonify({"error": "not found"}), 404
            allowed = False
            if user_from_token and user_from_token.id == rec.user_id:
                allowed = True
            elif current_user.is_authenticated and (int(current_user.get_id()) == rec.user_id or current_user.is_admin):
                allowed = True
            if not allowed:
                return jsonify({"error": "forbidden"}), 403
            atts = s.scalars(select(Attestation).where(Attestation.did_record_id == rec.id)).all()
        return jsonify({
            "did": rec.did_id,
            "didDocument": json.loads(rec.did_doc),
            "attestations": [json.loads(a.attestation) for a in atts],
            "kycStatus": rec.kyc_status,
        })

    # Public DID info (no auth): DID + DID Document + attestations
    @app.get("/api/dids/<int:did_id>/public")
    def api_did_public(did_id: int):
        with session_scope(Session) as s:
            rec = s.get(DidRecord, did_id)
            if not rec:
                return jsonify({"error": "not found"}), 404
            atts = s.scalars(select(Attestation).where(Attestation.did_record_id == rec.id)).all()
        return jsonify({
            "did": rec.did_id,
            "didDocument": json.loads(rec.did_doc),
            "attestations": [json.loads(a.attestation) for a in atts],
            "kycStatus": rec.kyc_status,
        })

    # Public API: fetch VC JSON (for integrators)
    @app.get("/api/credentials/<int:cred_id>")
    def api_credential_public(cred_id: int):
        with session_scope(Session) as s:
            cred = s.get(Credential, cred_id)
            if not cred:
                return jsonify({"error": "not found"}), 404
            return jsonify(json.loads(cred.vc_json))

    # Credential status endpoint for relying parties
    @app.get("/api/credentials/<int:cred_id>/status")
    def api_credential_status(cred_id: int):
        with session_scope(Session) as s:
            cred = s.get(Credential, cred_id)
            if not cred:
                return jsonify({"error": "not found"}), 404
            base = app.config.get("BASE_URL") or request.host_url.rstrip("/")
            return jsonify({
                "id": f"{base}/api/credentials/{cred_id}/status",
                "type": "SimpleStatus",
                "status": cred.status,
            })

    @app.get("/settings")
    @login_required
    def settings_page():
        # Do not display existing token; only show whether exists
        with session_scope(Session) as s:
            u = s.get(User, int(current_user.get_id()))
            has_token = bool(u.api_token_hash)
        return render_template("settings.html", has_token=has_token)

    @app.post("/settings/token")
    @login_required
    def settings_generate_token():
        import secrets
        token = secrets.token_urlsafe(32)
        h = hashlib.sha256(token.encode()).hexdigest()
        with session_scope(Session) as s:
            u = s.get(User, int(current_user.get_id()))
            u.api_token_hash = h
        flash(f"Your API token (save now, shown once): {token}", "info")
        return redirect(url_for("settings_page"))

    @app.post("/settings/token/revoke")
    @login_required
    def settings_revoke_token():
        with session_scope(Session) as s:
            u = s.get(User, int(current_user.get_id()))
            u.api_token_hash = None
        flash("API token revoked.", "info")
        return redirect(url_for("settings_page"))

    @app.get("/did/<int:did_id>/bundle")
    @login_required
    def did_bundle(did_id: int):
        with session_scope(Session) as s:
            rec = s.get(DidRecord, did_id)
            if not rec:
                return "Not found", 404
            if int(current_user.get_id()) != rec.user_id and not current_user.is_admin:
                return "Forbidden", 403
            atts = s.scalars(select(Attestation).where(Attestation.did_record_id == rec.id)).all()
        buf = BytesIO()
        with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
            z.writestr('did.json', rec.did_doc)
            for i, a in enumerate(atts, start=1):
                z.writestr(f'attestation_{i}.json', json.dumps(json.loads(a.attestation), indent=2))
        buf.seek(0)
        return send_file(buf, mimetype='application/zip', as_attachment=True, download_name=f"bundle_{did_id}.zip")

    # Generate 725 metadata for a specific credential (per-asset/project)
    @app.post("/did/<int:did_id>/credentials/<int:cred_id>/metadata")
    @login_required
    def credential_metadata(did_id: int, cred_id: int):
        with session_scope(Session) as s:
            rec = s.get(DidRecord, did_id)
            cred = s.get(Credential, cred_id)
            if not rec or not cred or cred.did_record_id != rec.id:
                return "Not found", 404
            if int(current_user.get_id()) != rec.user_id and not current_user.is_admin:
                return "Forbidden", 403
            if cred.status == 'revoked':
                flash("Credential is revoked; cannot generate metadata.", "error")
                return redirect(url_for("credential_detail", did_id=did_id, cred_id=cred_id))
        passphrase = request.form.get("key_passphrase", "")
        key_file = request.files.get("key_file")
        if key_file and key_file.filename:
            try:
                passphrase = key_file.read().decode().strip()
            except Exception:
                flash("Invalid key file", "error")
                return redirect(url_for("did_detail", did_id=did_id))
        if not passphrase:
            flash("Passphrase or key file required", "error")
            return redirect(url_for("did_detail", did_id=did_id))
        with session_scope(Session) as s:
            rec = s.get(DidRecord, did_id)
            try:
                priv = decrypt_with_passphrase(passphrase, rec.project_privkey_encrypted)
            except Exception:
                flash("Invalid passphrase", "error")
                return redirect(url_for("credential_detail", did_id=did_id, cred_id=cred_id))
            vc = json.loads(s.get(Credential, cred_id).vc_json)
            policy_id = (vc.get("credentialSubject", {}) or {}).get("policyID")
        if not policy_id:
            flash("Policy ID is required to generate 725 metadata. Create a credential with a policy ID.", "error")
            return redirect(url_for("credential_detail", did_id=did_id, cred_id=cred_id))
        collection_override = (request.form.get("collection_name") or "").strip()
        desc = (request.form.get("description") or "").strip()
        author = (request.form.get("author_name") or "").strip()
        did_name = desc or "Token-Identity"
        vc_name = desc or "Verification-Credential"
        if author:
            did_name = f"{did_name} — {author}"
            vc_name = f"{vc_name} — {author}"
        extra_files = None
        ti = TokenIdentity(policy_id=None, collection_name=rec.company, asset_name=None, social_accounts={}, website=[])
        mgr = PrismDIDManager(ti, privkey_hex=priv.hex())
        vc_url = url_for('api_credential_public', cred_id=cred_id, _external=True)
        try:
            md = mgr.create_token_metadata(
                rec.did_id,
                policy_id=policy_id,
                collection=collection_override or rec.company,
                vc_url=vc_url,
                did_name=did_name,
                vc_name=vc_name,
                extra_files=extra_files,
            )
            schema = json.load(open("token_identity/schemas/token_metadata.schema.json"))
            jsonschema_validate(md, schema)
        except Exception as e:
            flash(f"Metadata generation failed: {e}", "error")
            return redirect(url_for("credential_detail", did_id=did_id, cred_id=cred_id))
        # Save versioned file and redirect back to detail with preview
        from datetime import datetime as _dt
        meta_dir = os.path.join(app.config["UPLOAD_FOLDER"], "metadata", f"cred_{cred_id}")
        os.makedirs(meta_dir, exist_ok=True)
        fname = _dt.utcnow().strftime("%Y%m%dT%H%M%SZ") + ".json"
        saved_path = os.path.join(meta_dir, fname)
        with open(saved_path, "w", encoding="utf-8") as f:
            json.dump(md, f, indent=2)
        flash("Metadata generated and saved.", "info")
        return redirect(url_for("credential_detail", did_id=did_id, cred_id=cred_id, md=fname))

    @app.get("/did/<int:did_id>/credentials/<int:cred_id>/metadata/download")
    @login_required
    def credential_metadata_download(did_id: int, cred_id: int):
        with session_scope(Session) as s:
            rec = s.get(DidRecord, did_id)
            cred = s.get(Credential, cred_id)
            if not rec or not cred or cred.did_record_id != rec.id:
                return "Not found", 404
            if int(current_user.get_id()) != rec.user_id and not current_user.is_admin:
                return "Forbidden", 403
        meta_dir = os.path.join(app.config["UPLOAD_FOLDER"], "metadata", f"cred_{cred_id}")
        file_name = request.args.get("file", "")
        if file_name:
            safe = os.path.normpath(os.path.join(meta_dir, file_name))
            if os.path.commonpath([safe, meta_dir]) != meta_dir or not os.path.exists(safe):
                return "Not found", 404
            return send_file(safe, mimetype="application/json", as_attachment=True, download_name=file_name)
        # If no file param provided, deliver latest if any
        if not os.path.isdir(meta_dir):
            return "Not found", 404
        files = [f for f in os.listdir(meta_dir) if f.endswith('.json')]
        if not files:
            return "Not found", 404
        files.sort(reverse=True)
        path = os.path.join(meta_dir, files[0])
        return send_file(path, mimetype="application/json", as_attachment=True, download_name=files[0])

    # Revoke a credential
    @app.post("/did/<int:did_id>/credentials/<int:cred_id>/revoke")
    @login_required
    def credential_revoke(did_id: int, cred_id: int):
        reason = request.form.get("reason", "")
        with session_scope(Session) as s:
            rec = s.get(DidRecord, did_id)
            cred = s.get(Credential, cred_id)
            if not rec or not cred or cred.did_record_id != rec.id:
                return "Not found", 404
            if int(current_user.get_id()) != rec.user_id and not current_user.is_admin:
                return "Forbidden", 403
            from datetime import datetime as _dt
            cred.status = 'revoked'
            cred.revoked_reason = reason
            cred.revoked_at = _dt.utcnow()
            s.add(AuditLog(user_id=int(current_user.get_id()), action="revoke_vc", target=rec.did_id, message=f"cred:{cred.id} {reason}"))
        flash("Credential revoked.", "info")
        return redirect(url_for("credential_detail", did_id=did_id, cred_id=cred_id))

    @app.get("/healthz")
    def health():
        return {"status": "ok"}

    # About / One-Pager
    @app.get("/about")
    def about():
        return render_template("about.html")

    # Wizard: Step 1 - Start
    @app.get("/wizard/start")
    @login_required
    def wizard_start():
        form = DIDCreateForm()
        return render_template("wizard_start.html", form=form)

    @app.post("/wizard/start")
    @login_required
    def wizard_start_post():
        # Reuse submit logic by calling the same function code
        return submit()

    # Wizard: Step 2 - KYC Upload
    @app.get("/wizard/<int:did_id>/key")
    @login_required
    def wizard_key(did_id: int):
        with session_scope(Session) as s:
            rec = s.get(DidRecord, did_id)
            if not rec:
                return "Not found", 404
            if int(current_user.get_id()) != rec.user_id and not current_user.is_admin:
                return "Forbidden", 403
        has_key = bool(session.get(f"key_{did_id}"))
        confirmed = bool(session.get(f"key_confirmed_{did_id}"))
        return render_template("wizard_key.html", rec=rec, has_key=has_key, confirmed=confirmed)

    @app.post("/wizard/<int:did_id>/key/confirm")
    @login_required
    def wizard_key_confirm(did_id: int):
        with session_scope(Session) as s:
            rec = s.get(DidRecord, did_id)
            if not rec:
                return "Not found", 404
            if int(current_user.get_id()) != rec.user_id and not current_user.is_admin:
                return "Forbidden", 403
        if request.form.get("confirmed") != "on":
            flash("Please confirm that you have downloaded and safely stored your key.", "error")
            return redirect(url_for("wizard_key", did_id=did_id))
        session[f"key_confirmed_{did_id}"] = True
        return redirect(url_for("wizard_kyc", did_id=did_id))

    @app.get("/wizard/<int:did_id>/kyc")
    @login_required
    def wizard_kyc(did_id: int):
        with session_scope(Session) as s:
            rec = s.get(DidRecord, did_id)
            if not rec:
                return "Not found", 404
            if int(current_user.get_id()) != rec.user_id and not current_user.is_admin:
                return "Forbidden", 403
            # Enforce key confirmation before KYC
            if not session.get(f"key_confirmed_{did_id}"):
                return redirect(url_for("wizard_key", did_id=did_id))
            docs = s.scalars(select(Document).where(Document.did_record_id == rec.id)).all()
        upload_action = url_for('did_upload', did_id=did_id) + f"?next={url_for('wizard_kyc', did_id=did_id)}"
        has_key = bool(session.get(f"key_{did_id}"))
        return render_template("wizard_kyc.html", rec=rec, documents=docs, upload_action=upload_action, has_key=has_key)

    @app.post("/wizard/<int:did_id>/submit")
    @login_required
    def wizard_submit(did_id: int):
        with session_scope(Session) as s:
            rec = s.get(DidRecord, did_id)
            if not rec:
                return "Not found", 404
            if int(current_user.get_id()) != rec.user_id and not current_user.is_admin:
                return "Forbidden", 403
            rec.kyc_status = "submitted"
            s.add(AuditLog(user_id=int(current_user.get_id()), action="submit_kyc", target=rec.did_id, message=""))
        return redirect(url_for("wizard_review", did_id=did_id))

    # Wizard: Step 3 - Review/Approval
    @app.get("/wizard/<int:did_id>/review")
    @login_required
    def wizard_review(did_id: int):
        with session_scope(Session) as s:
            rec = s.get(DidRecord, did_id)
            if not rec:
                return "Not found", 404
            if int(current_user.get_id()) != rec.user_id and not current_user.is_admin:
                return "Forbidden", 403
            atts = s.scalars(select(Attestation).where(Attestation.did_record_id == rec.id)).all()
        return render_template("wizard_review.html", rec=rec, attestations=atts)

    return app


if __name__ == "__main__":
    app = create_app()
    # Dev server; for production, run via WSGI/ASGI server
    app.run(host="0.0.0.0", port=8000, debug=True)
