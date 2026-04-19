"""nmkr-identity command-line interface.

Offers two groups of commands:
  - Local (offline): key/did/vc/metadata/verify operations that only use the
    token_identity library and produce JSON artifacts.
  - Remote: talks to an identity.nmkr.io-compatible platform using a bearer
    token, to create DIDs and credentials on the server.

The `remote` commands are wired in cli_remote.py and attached here.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from .crypto import gen_secp256k1_keypair, jwk_from_verifying_key
from .models import TokenIdentity
from .prism_did import PrismDIDManager


# ---------- I/O helpers ----------

def _load_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _dump_json(path: Optional[str], obj: Dict[str, Any]) -> None:
    data = json.dumps(obj, indent=2)
    if path:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(data + "\n")
        _info(f"Wrote {path}")
    else:
        print(data)


def _read_privkey(args: argparse.Namespace) -> Optional[str]:
    """Resolve a private key in hex from --privkey-hex, --privkey-file, or env."""
    hex_val = getattr(args, "privkey_hex", None)
    if hex_val:
        return hex_val.strip()
    path = getattr(args, "privkey_file", None)
    if path:
        return Path(path).read_text(encoding="utf-8").strip()
    env = os.environ.get("NMKR_IDENTITY_PRIVKEY_HEX")
    if env:
        return env.strip()
    return None


# ---------- output helpers ----------

_USE_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def _c(code: str, s: str) -> str:
    if not _USE_COLOR:
        return s
    return f"\x1b[{code}m{s}\x1b[0m"


def _info(msg: str) -> None:
    print(_c("2", msg), file=sys.stderr)


def _err(msg: str) -> None:
    print(_c("31", f"error: {msg}"), file=sys.stderr)


def _ok(msg: str) -> None:
    print(_c("32", msg), file=sys.stderr)


# ---------- key commands ----------

def cmd_key_new(args: argparse.Namespace) -> int:
    sk, vk = gen_secp256k1_keypair()
    out = {
        "privateKeyHex": sk.to_string().hex(),
        "publicKeyJwk": jwk_from_verifying_key(vk),
    }
    _dump_json(args.out, out)
    if not args.out:
        _info("⚠ Save the private key somewhere safe — it cannot be recovered.")
    return 0


def cmd_key_pubkey(args: argparse.Namespace) -> int:
    from ecdsa import SigningKey, SECP256k1

    priv = _read_privkey(args)
    if not priv:
        _err("private key required (--privkey-hex, --privkey-file, or NMKR_IDENTITY_PRIVKEY_HEX)")
        return 2
    sk = SigningKey.from_string(bytes.fromhex(priv), curve=SECP256k1)
    _dump_json(args.out, jwk_from_verifying_key(sk.get_verifying_key()))
    return 0


# ---------- local DID / VC / metadata ----------

def _build_token_identity(
    policy_id: Optional[str],
    collection: str,
    asset: Optional[str],
    twitter: Optional[List[str]],
    discord: Optional[List[str]],
    website: Optional[List[str]],
    rwa_asset_type: Optional[str],
    rwa_jurisdiction: Optional[str],
    rwa_registration: Optional[str],
) -> TokenIdentity:
    social: Dict[str, List[str]] = {}
    if twitter:
        social["twitter"] = twitter
    if discord:
        social["discord"] = discord
    rwa = None
    if rwa_asset_type or rwa_jurisdiction or rwa_registration:
        rwa = {
            k: v
            for k, v in {
                "assetType": rwa_asset_type,
                "jurisdiction": rwa_jurisdiction,
                "registrationNumber": rwa_registration,
            }.items()
            if v is not None
        }
    return TokenIdentity(
        policy_id=policy_id,
        collection_name=collection,
        asset_name=asset,
        social_accounts=social,
        website=website or [],
        rwa_details=rwa,
    )


def cmd_did_create(args: argparse.Namespace) -> int:
    ti = _build_token_identity(
        args.policy_id,
        args.collection,
        args.asset,
        args.twitter,
        args.discord,
        args.website,
        args.rwa_asset_type,
        args.rwa_jurisdiction,
        args.rwa_registration,
    )
    priv = _read_privkey(args)
    manager = PrismDIDManager(ti, privkey_hex=priv)
    did_doc = manager.create_did_document()
    _dump_json(args.out, did_doc)
    if not priv:
        priv_hex = manager.export_privkey_hex()
        _info("")
        _info("Generated a new private key (hex):")
        _info(_c("1", priv_hex))
        _info("⚠ Store it securely — needed to sign credentials + 725 metadata.")
    return 0


def cmd_vc_issue(args: argparse.Namespace) -> int:
    did_doc = _load_json(args.did)
    did = did_doc["id"]
    collection = args.collection or did_doc.get("payload", {}).get("collectionName") or did
    priv = _read_privkey(args)
    if not priv:
        _err("private key required to sign VC")
        return 2
    rwa = None
    if args.rwa_asset_type or args.rwa_jurisdiction or args.rwa_registration:
        rwa = {
            k: v
            for k, v in {
                "assetType": args.rwa_asset_type,
                "jurisdiction": args.rwa_jurisdiction,
                "registrationNumber": args.rwa_registration,
            }.items()
            if v is not None
        }
    ti = TokenIdentity(
        policy_id=args.policy_id,
        collection_name=collection,
        asset_name=args.asset,
        social_accounts={},
        website=[],
        rwa_details=rwa,
    )
    manager = PrismDIDManager(ti, privkey_hex=priv)
    vc = manager.create_company_vc(
        did,
        policy_id=args.policy_id,
        asset_name=args.asset,
        rwa_details=rwa,
        label=args.label,
    )
    _dump_json(args.out, vc)
    return 0


def cmd_metadata_generate(args: argparse.Namespace) -> int:
    did_doc = _load_json(args.did)
    priv = _read_privkey(args)
    if not priv:
        _err("private key required to sign metadata")
        return 2
    ti = TokenIdentity(
        policy_id=args.policy_id,
        collection_name=args.collection,
        asset_name=None,
        social_accounts={},
        website=[],
    )
    manager = PrismDIDManager(ti, privkey_hex=priv)
    md = manager.create_token_metadata(
        did_doc["id"],
        policy_id=args.policy_id,
        collection=args.collection,
        vc_url=args.vc_url,
        did_name=args.did_name or "Token-Identity",
        vc_name=args.vc_name or "Verification-Credential",
    )
    _dump_json(args.out, md)
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    did_doc = _load_json(args.did)
    md = _load_json(args.metadata)

    policy_ids = [k for k in md.get("725", {}).keys() if k != "version"]
    if not policy_ids:
        _err("invalid metadata: missing policy id under 725")
        return 2
    policy_id = policy_ids[0]
    collections = list(md["725"][policy_id].keys())
    if not collections:
        _err("invalid metadata: missing collection name")
        return 2
    collection = collections[0]

    # If the DID payload doesn't pin a policy, don't enforce the metadata's one.
    did_payload = did_doc.get("payload", {}) or {}
    expected_policy = did_payload.get("policyID") or None

    ti = TokenIdentity(
        policy_id=expected_policy,
        collection_name=collection,
        asset_name=None,
        social_accounts={},
        website=[],
    )
    manager = PrismDIDManager(ti, privkey_hex=_read_privkey(args))
    did_ok = manager.verify_did_document(did_doc)
    md_ok = manager.verify_metadata(md, did_doc["id"])
    result = {"did_valid": did_ok, "metadata_valid": md_ok}
    _dump_json(None, result)
    return 0 if (did_ok and md_ok) else 3


# ---------- parser wiring ----------

def _add_rwa_flags(p: argparse.ArgumentParser) -> None:
    p.add_argument("--rwa-asset-type")
    p.add_argument("--rwa-jurisdiction")
    p.add_argument("--rwa-registration")


def _add_privkey_flags(p: argparse.ArgumentParser) -> None:
    p.add_argument("--privkey-hex", help="32-byte hex private key (or set NMKR_IDENTITY_PRIVKEY_HEX)")
    p.add_argument("--privkey-file", help="Path to a file containing the hex private key")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="nmkr-identity",
        description="NMKR Identity CLI — local DID/VC tools and remote platform client",
    )
    root = p.add_subparsers(dest="command", required=True)

    # key
    key = root.add_parser("key", help="Keypair utilities")
    key_sub = key.add_subparsers(dest="sub", required=True)
    k_new = key_sub.add_parser("new", help="Generate a new secp256k1 keypair")
    k_new.add_argument("--out")
    k_new.set_defaults(func=cmd_key_new)
    k_pub = key_sub.add_parser("pubkey", help="Derive public JWK from a private hex key")
    _add_privkey_flags(k_pub)
    k_pub.add_argument("--out")
    k_pub.set_defaults(func=cmd_key_pubkey)

    # did
    did = root.add_parser("did", help="DID Document commands (local)")
    did_sub = did.add_subparsers(dest="sub", required=True)
    d_create = did_sub.add_parser("create", help="Create a self-signed DID Document")
    d_create.add_argument("--collection", required=True, help="Company / collection name")
    d_create.add_argument("--policy-id")
    d_create.add_argument("--asset")
    d_create.add_argument("--twitter", nargs="*")
    d_create.add_argument("--discord", nargs="*")
    d_create.add_argument("--website", nargs="*")
    _add_rwa_flags(d_create)
    _add_privkey_flags(d_create)
    d_create.add_argument("--out")
    d_create.set_defaults(func=cmd_did_create)

    # vc
    vc = root.add_parser("vc", help="Verifiable Credential commands (local)")
    vc_sub = vc.add_subparsers(dest="sub", required=True)
    v_issue = vc_sub.add_parser("issue", help="Issue a VC signed by a DID key")
    v_issue.add_argument("--did", required=True, help="Path to a DID Document JSON file")
    v_issue.add_argument("--label", required=True, help="Human label for the credential")
    v_issue.add_argument("--policy-id")
    v_issue.add_argument("--asset")
    v_issue.add_argument("--collection", help="Override collection name from DID")
    _add_rwa_flags(v_issue)
    _add_privkey_flags(v_issue)
    v_issue.add_argument("--out")
    v_issue.set_defaults(func=cmd_vc_issue)

    # metadata
    md = root.add_parser("metadata", help="CIP-725 metadata commands (local)")
    md_sub = md.add_subparsers(dest="sub", required=True)
    m_gen = md_sub.add_parser("generate", help="Generate signed 725 metadata referencing a DID")
    m_gen.add_argument("--did", required=True)
    m_gen.add_argument("--policy-id", required=True)
    m_gen.add_argument("--collection", required=True)
    m_gen.add_argument("--vc-url")
    m_gen.add_argument("--did-name")
    m_gen.add_argument("--vc-name")
    _add_privkey_flags(m_gen)
    m_gen.add_argument("--out")
    m_gen.set_defaults(func=cmd_metadata_generate)

    # verify
    ver = root.add_parser("verify", help="Verify a DID + 725 metadata pair")
    ver.add_argument("--did", required=True)
    ver.add_argument("--metadata", required=True)
    _add_privkey_flags(ver)
    ver.set_defaults(func=cmd_verify)

    # Legacy flat commands kept as deprecated aliases for the pre-2026-04 CLI.
    legacy_did = root.add_parser("generate-did", help="(deprecated) alias of `did create`")
    legacy_did.add_argument("--policy-id", required=True)
    legacy_did.add_argument("--collection", required=True)
    legacy_did.add_argument("--asset")
    legacy_did.add_argument("--twitter", nargs="*")
    legacy_did.add_argument("--discord", nargs="*")
    legacy_did.add_argument("--website", nargs="*")
    _add_rwa_flags(legacy_did)
    _add_privkey_flags(legacy_did)
    legacy_did.add_argument("--out")
    legacy_did.set_defaults(func=cmd_did_create)

    legacy_meta = root.add_parser("generate-metadata", help="(deprecated) alias of `metadata generate`")
    legacy_meta.add_argument("--did", required=True)
    legacy_meta.add_argument("--policy-id", required=True)
    legacy_meta.add_argument("--collection", required=True)
    legacy_meta.add_argument("--vc-url")
    legacy_meta.add_argument("--did-name")
    legacy_meta.add_argument("--vc-name")
    _add_privkey_flags(legacy_meta)
    legacy_meta.add_argument("--out")
    legacy_meta.set_defaults(func=cmd_metadata_generate)

    # remote (attached lazily so stdlib-only environments still import cli.py)
    remote = root.add_parser("remote", help="Talk to an identity.nmkr.io platform")
    try:
        from . import cli_remote

        cli_remote.attach(remote)
    except Exception as e:  # pragma: no cover
        remote.description = f"(remote subsystem failed to load: {e})"
        remote.set_defaults(func=lambda _a: (_err(f"remote unavailable: {e}") or 4))

    return p


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        _err("interrupted")
        return 130
    except Exception as e:  # pragma: no cover - last-chance safety net
        _err(str(e))
        return 1


if __name__ == "__main__":
    sys.exit(main())
