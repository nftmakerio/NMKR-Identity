from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

from .models import TokenIdentity
from .prism_did import PrismDIDManager


def _load_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _dump_json(path: str | None, obj: Dict[str, Any]):
    data = json.dumps(obj, indent=2)
    if path:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(data + "\n")
    else:
        print(data)


def cmd_generate_did(args: argparse.Namespace) -> int:
    social: Dict[str, List[str]] = {}
    if args.twitter:
        social["twitter"] = args.twitter
    if args.discord:
        social["discord"] = args.discord
    website = args.website or []
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
        collection_name=args.collection,
        asset_name=args.asset,
        social_accounts=social,
        website=website,
        rwa_details=rwa,
    )
    manager = PrismDIDManager(ti, privkey_hex=args.privkey_hex)
    did_doc = manager.create_did_document()
    _dump_json(args.out, did_doc)
    return 0


def cmd_generate_metadata(args: argparse.Namespace) -> int:
    did_doc = _load_json(args.did)
    did = did_doc["id"]
    social: Dict[str, List[str]] = {}
    # Minimal identity for context (policy/collection) used to sign/verify metadata
    ti = TokenIdentity(
        policy_id=args.policy_id,
        collection_name=args.collection,
        asset_name=None,
        social_accounts=social,
        website=[],
        rwa_details=None,
    )
    manager = PrismDIDManager(ti, privkey_hex=args.privkey_hex)
    md = manager.create_token_metadata(did)
    _dump_json(args.out, md)
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    did_doc = _load_json(args.did)
    md = _load_json(args.metadata)

    # Extract minimal identity context from metadata for verification
    policy_ids = [k for k in md.get("725", {}).keys() if k != "version"]
    if not policy_ids:
        print("Invalid metadata: missing policy id under 725", file=sys.stderr)
        return 2
    policy_id = policy_ids[0]
    collections = list(md["725"][policy_id].keys())
    if not collections:
        print("Invalid metadata: missing collection name", file=sys.stderr)
        return 2
    collection = collections[0]

    ti = TokenIdentity(
        policy_id=policy_id,
        collection_name=collection,
        asset_name=None,
        social_accounts={},
        website=[],
    )
    manager = PrismDIDManager(ti, privkey_hex=args.privkey_hex)
    did_ok = manager.verify_did_document(did_doc)
    md_ok = manager.verify_metadata(md, did_doc["id"])

    result = {"did_valid": did_ok, "metadata_valid": md_ok}
    _dump_json(None, result)
    return 0 if (did_ok and md_ok) else 3


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="token-identity", description="Token Identity (Atala PRISM DID) tools")
    sub = p.add_subparsers(dest="command", required=True)

    g1 = sub.add_parser("generate-did", help="Create a DID Document for a collection/token")
    g1.add_argument("--policy-id", required=True)
    g1.add_argument("--collection", required=True)
    g1.add_argument("--asset")
    g1.add_argument("--twitter", nargs="*")
    g1.add_argument("--discord", nargs="*")
    g1.add_argument("--website", nargs="*")
    g1.add_argument("--rwa-asset-type")
    g1.add_argument("--rwa-jurisdiction")
    g1.add_argument("--rwa-registration")
    g1.add_argument("--privkey-hex", help="32-byte hex private key for signing")
    g1.add_argument("--out", help="Output file for DID Document (JSON)")
    g1.set_defaults(func=cmd_generate_did)

    g2 = sub.add_parser("generate-metadata", help="Create Token Metadata linking to DID")
    g2.add_argument("--did", required=True, help="DID Document JSON path")
    g2.add_argument("--policy-id", required=True)
    g2.add_argument("--collection", required=True)
    g2.add_argument("--privkey-hex", help="32-byte hex private key used for signing metadata")
    g2.add_argument("--out", help="Output file for metadata JSON")
    g2.set_defaults(func=cmd_generate_metadata)

    g3 = sub.add_parser("verify", help="Verify DID Document and Token Metadata")
    g3.add_argument("--did", required=True)
    g3.add_argument("--metadata", required=True)
    g3.add_argument("--privkey-hex", help="32-byte hex private key that corresponds to DID public key")
    g3.set_defaults(func=cmd_verify)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

