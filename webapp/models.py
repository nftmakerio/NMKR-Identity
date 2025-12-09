from __future__ import annotations

import json
from datetime import datetime
from typing import Optional

from sqlalchemy import Integer, String, DateTime, ForeignKey, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    api_token_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    is_admin: Mapped[int] = mapped_column(Integer, default=0)  # 0/1
    email_verified: Mapped[int] = mapped_column(Integer, default=0)  # 0/1
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    dids: Mapped[list[DidRecord]] = relationship("DidRecord", back_populates="user")


class DidRecord(Base):
    __tablename__ = "did_records"
    __table_args__ = (UniqueConstraint("did_id", name="uq_did_id"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    company: Mapped[str] = mapped_column(String(255))
    website: Mapped[str] = mapped_column(Text, default="")  # space-separated
    twitter: Mapped[str] = mapped_column(Text, default="")
    discord: Mapped[str] = mapped_column(Text, default="")
    policy_id: Mapped[str] = mapped_column(String(128))
    asset_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    did_id: Mapped[str] = mapped_column(String(128))
    did_doc: Mapped[str] = mapped_column(Text)  # JSON string
    project_privkey_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    did_pubkey_jwk: Mapped[str | None] = mapped_column(Text, nullable=True)
    kyc_status: Mapped[str] = mapped_column(String(32), default="pending")  # pending, approved, rejected
    kyc_notes: Mapped[str] = mapped_column(Text, default="")
    kyc_decision_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    user: Mapped[User] = relationship("User", back_populates="dids")
    attestations: Mapped[list[Attestation]] = relationship("Attestation", back_populates="did_record")
    credentials: Mapped[list[Credential]] = relationship("Credential", back_populates="did_record")


class Attestation(Base):
    __tablename__ = "attestations"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    did_record_id: Mapped[int] = mapped_column(ForeignKey("did_records.id"))
    attester_did: Mapped[str] = mapped_column(String(128))
    attestation: Mapped[str] = mapped_column(Text)  # JSON string
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    did_record: Mapped[DidRecord] = relationship("DidRecord", back_populates="attestations")


class Credential(Base):
    __tablename__ = "credentials"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    did_record_id: Mapped[int] = mapped_column(ForeignKey("did_records.id"))
    label: Mapped[str] = mapped_column(String(255))
    vc_json: Mapped[str] = mapped_column(Text)  # JSON string of the VC
    status: Mapped[str] = mapped_column(String(32), default="active")  # active, revoked
    revoked_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    did_record: Mapped[DidRecord] = relationship("DidRecord", back_populates="credentials")


class Document(Base):
    __tablename__ = "documents"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    did_record_id: Mapped[int] = mapped_column(ForeignKey("did_records.id"))
    filename: Mapped[str] = mapped_column(String(512))
    stored_path: Mapped[str] = mapped_column(String(1024))
    uploaded_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    action: Mapped[str] = mapped_column(String(255))
    target: Mapped[str] = mapped_column(String(255))
    message: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class EmailToken(Base):
    __tablename__ = "email_tokens"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    token: Mapped[str] = mapped_column(String(128), unique=True)
    purpose: Mapped[str] = mapped_column(String(32))  # verify, reset
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
