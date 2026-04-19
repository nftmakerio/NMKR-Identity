"""Remote subcommands for the nmkr-identity CLI.

Wires argparse subparsers that call into the HTTP client in ``remote.py``.
Kept separate so the local (offline) CLI doesn't pay any import cost from it.
"""
from __future__ import annotations

import argparse
import getpass
import json
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from .remote import Client, Config, RemoteError


# ---------- output ----------

def _print_json(obj: Any, out: Optional[str] = None) -> None:
    data = json.dumps(obj, indent=2, default=str)
    if out:
        Path(out).parent.mkdir(parents=True, exist_ok=True)
        Path(out).write_text(data + "\n", encoding="utf-8")
        print(f"wrote {out}", file=sys.stderr)
    else:
        print(data)


def _call(fn: Callable[[], Any], out: Optional[str] = None) -> int:
    try:
        result = fn()
    except RemoteError as e:
        print(f"error: {e}", file=sys.stderr)
        if e.body:
            try:
                print(json.dumps(e.body, indent=2, default=str), file=sys.stderr)
            except Exception:
                print(str(e.body), file=sys.stderr)
        return 1
    if result is not None:
        _print_json(result, out)
    return 0


# ---------- privkey resolution ----------

def _resolve_signing_auth(args: argparse.Namespace) -> Dict[str, str]:
    """Build the {"privkey_hex": ...} or {"passphrase": ...} part of a payload."""
    if getattr(args, "privkey_hex", None):
        return {"privkey_hex": args.privkey_hex.strip()}
    if getattr(args, "privkey_file", None):
        return {"privkey_hex": Path(args.privkey_file).read_text(encoding="utf-8").strip()}
    if getattr(args, "passphrase", None):
        return {"passphrase": args.passphrase}
    if getattr(args, "passphrase_file", None):
        return {"passphrase": Path(args.passphrase_file).read_text(encoding="utf-8").strip()}
    raise SystemExit("error: need --privkey-hex, --privkey-file, --passphrase, or --passphrase-file")


# ---------- commands ----------

def cmd_login(args: argparse.Namespace) -> int:
    cfg = Config.load()
    if args.url:
        cfg.url = args.url.rstrip("/")
    token = args.token
    if not token:
        try:
            token = getpass.getpass("API token: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\naborted", file=sys.stderr)
            return 130
    if not token:
        print("error: empty token", file=sys.stderr)
        return 2
    cfg.token = token
    cfg.save()
    # probe
    try:
        who = Client(cfg).whoami()
        print(f"logged in to {cfg.url} as {who.get('email', '?')}", file=sys.stderr)
    except RemoteError as e:
        print(f"warning: token saved but verification failed ({e})", file=sys.stderr)
        return 1
    return 0


def cmd_logout(_args: argparse.Namespace) -> int:
    cfg = Config.load()
    cfg.clear_token()
    print("logged out", file=sys.stderr)
    return 0


def cmd_whoami(args: argparse.Namespace) -> int:
    return _call(lambda: Client().whoami(), out=getattr(args, "out", None))


# DID

def cmd_did_create(args: argparse.Namespace) -> int:
    payload: Dict[str, Any] = {
        "company": args.company,
        "website": _split(args.website),
        "twitter": _split(args.twitter),
        "discord": _split(args.discord),
    }
    for key, val in {
        "legal_name": args.legal_name,
        "industry": args.industry,
        "country": args.country,
        "registration_number": args.registration_number,
        "contact_email": args.contact_email,
        "contact_url": args.contact_url,
        "description": args.description,
    }.items():
        if val:
            payload[key] = val
    return _call(lambda: Client().did_create(payload), out=args.out)


def cmd_did_list(args: argparse.Namespace) -> int:
    return _call(lambda: Client().did_list(), out=args.out)


def cmd_did_get(args: argparse.Namespace) -> int:
    return _call(lambda: Client().did_get(args.did_id), out=args.out)


# VC

def cmd_vc_issue(args: argparse.Namespace) -> int:
    payload: Dict[str, Any] = {"label": args.label}
    payload.update(_resolve_signing_auth(args))
    if args.policy_id:
        payload["policy_id"] = args.policy_id
    if args.asset:
        payload["asset_name"] = args.asset
    rwa = {
        k: v
        for k, v in {
            "assetType": args.rwa_asset_type,
            "jurisdiction": args.rwa_jurisdiction,
            "registrationNumber": args.rwa_registration,
        }.items()
        if v
    }
    if rwa:
        payload["rwa_details"] = rwa
    return _call(lambda: Client().vc_issue(args.did_id, payload), out=args.out)


def cmd_vc_list(args: argparse.Namespace) -> int:
    return _call(lambda: Client().vc_list(args.did_id), out=args.out)


def cmd_vc_get(args: argparse.Namespace) -> int:
    return _call(lambda: Client().vc_get(args.cred_id), out=args.out)


def cmd_vc_revoke(args: argparse.Namespace) -> int:
    return _call(lambda: Client().vc_revoke(args.cred_id, reason=args.reason), out=args.out)


def cmd_vc_metadata(args: argparse.Namespace) -> int:
    payload: Dict[str, Any] = {}
    payload.update(_resolve_signing_auth(args))
    for key, val in {
        "description": args.description,
        "author_name": args.author,
        "collection_name": args.collection,
    }.items():
        if val:
            payload[key] = val
    return _call(lambda: Client().vc_metadata(args.cred_id, payload), out=args.out)


# ---------- helpers ----------

def _split(value: Optional[List[str] | str]) -> List[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [v for v in value if v]
    return [v for v in value.split() if v]


def _add_signing_flags(p: argparse.ArgumentParser) -> None:
    grp = p.add_argument_group("signing key (pick one)")
    grp.add_argument("--privkey-hex", help="Raw 32-byte hex private key")
    grp.add_argument("--privkey-file", help="File containing the hex private key")
    grp.add_argument("--passphrase", help="Passphrase that decrypts the server-stored key")
    grp.add_argument("--passphrase-file", help="File containing the passphrase")


def _add_rwa_flags(p: argparse.ArgumentParser) -> None:
    p.add_argument("--rwa-asset-type")
    p.add_argument("--rwa-jurisdiction")
    p.add_argument("--rwa-registration")


def attach(parser: argparse.ArgumentParser) -> None:
    """Attach the remote subcommand tree to ``parser``."""
    sub = parser.add_subparsers(dest="remote_sub", required=True)

    p = sub.add_parser("login", help="Save an API token to ~/.nmkr-identity/config.json")
    p.add_argument("--token")
    p.add_argument("--url", help=f"Platform URL (default {Config.load().url})")
    p.set_defaults(func=cmd_login)

    p = sub.add_parser("logout", help="Clear the saved API token")
    p.set_defaults(func=cmd_logout)

    p = sub.add_parser("whoami", help="Show the authenticated account")
    p.add_argument("--out")
    p.set_defaults(func=cmd_whoami)

    # did
    did = sub.add_parser("did", help="DID operations on the platform")
    did_sub = did.add_subparsers(dest="did_sub", required=True)

    d = did_sub.add_parser("create", help="Create a company DID")
    d.add_argument("--company", required=True)
    d.add_argument("--website")
    d.add_argument("--twitter")
    d.add_argument("--discord")
    d.add_argument("--legal-name")
    d.add_argument("--industry")
    d.add_argument("--country")
    d.add_argument("--registration-number")
    d.add_argument("--contact-email")
    d.add_argument("--contact-url")
    d.add_argument("--description")
    d.add_argument("--out")
    d.set_defaults(func=cmd_did_create)

    d = did_sub.add_parser("list", help="List my DIDs")
    d.add_argument("--out")
    d.set_defaults(func=cmd_did_list)

    d = did_sub.add_parser("get", help="Get a DID by numeric id")
    d.add_argument("did_id", type=int)
    d.add_argument("--out")
    d.set_defaults(func=cmd_did_get)

    # vc
    vc = sub.add_parser("vc", help="Credential operations on the platform")
    vc_sub = vc.add_subparsers(dest="vc_sub", required=True)

    v = vc_sub.add_parser("issue", help="Issue a VC signed by the DID's key")
    v.add_argument("--did-id", type=int, required=True)
    v.add_argument("--label", required=True)
    v.add_argument("--policy-id")
    v.add_argument("--asset")
    _add_rwa_flags(v)
    _add_signing_flags(v)
    v.add_argument("--out")
    v.set_defaults(func=cmd_vc_issue)

    v = vc_sub.add_parser("list", help="List credentials on a DID")
    v.add_argument("--did-id", type=int, required=True)
    v.add_argument("--out")
    v.set_defaults(func=cmd_vc_list)

    v = vc_sub.add_parser("get", help="Get a credential by id")
    v.add_argument("cred_id", type=int)
    v.add_argument("--out")
    v.set_defaults(func=cmd_vc_get)

    v = vc_sub.add_parser("revoke", help="Revoke a credential")
    v.add_argument("cred_id", type=int)
    v.add_argument("--reason", default="")
    v.add_argument("--out")
    v.set_defaults(func=cmd_vc_revoke)

    v = vc_sub.add_parser("metadata", help="Generate signed CIP-725 metadata for a credential")
    v.add_argument("cred_id", type=int)
    v.add_argument("--description")
    v.add_argument("--author")
    v.add_argument("--collection")
    _add_signing_flags(v)
    v.add_argument("--out")
    v.set_defaults(func=cmd_vc_metadata)
