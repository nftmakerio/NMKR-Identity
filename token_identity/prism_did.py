from __future__ import annotations

import json
import time
import hashlib
from dataclasses import asdict
from typing import Any, Dict, Optional

from .models import TokenIdentity
from .crypto import (
    gen_secp256k1_keypair,
    jwk_from_verifying_key,
    sign_det_secp256k1,
    verify_sig_secp256k1,
    b64url_encode,
    b64url_decode,
)


class PrismDIDManager:
    def __init__(self, token_identity: TokenIdentity, privkey_hex: Optional[str] = None, seed: Optional[bytes] = None):
        self.token_identity = token_identity
        if privkey_hex:
            from ecdsa import SigningKey, SECP256k1
            sk = SigningKey.from_string(bytes.fromhex(privkey_hex), curve=SECP256k1)
            vk = sk.get_verifying_key()
            self._sk, self._vk = sk, vk
        else:
            self._sk, self._vk = gen_secp256k1_keypair(seed=seed)

    # Public API
    def create_did_document(self) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "date": time.strftime("%Y-%m-%d"),
            "accounts": self.token_identity.social_accounts,
            "website": self.token_identity.website,
        }
        if self.token_identity.policy_id:
            payload["policyID"] = self.token_identity.policy_id
        if self.token_identity.asset_name:
            payload["assetName"] = self.token_identity.asset_name
        if self.token_identity.rwa_details:
            payload["rwaDetails"] = self.token_identity.rwa_details
        if self.token_identity.extra_payload:
            # Merge any additional fields into payload before signing
            try:
                for k, v in self.token_identity.extra_payload.items():
                    payload[k] = v
            except Exception:
                pass

        did_id = f"did:prism:{self._generate_did_suffix()}"

        document: Dict[str, Any] = {
            "@context": [
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/suites/jws-2020/v1",
            ],
            "id": did_id,
            "payload": payload,
            "verificationMethod": [
                {
                    "id": "#master-0",
                    "type": "JsonWebKey2020",
                    "controller": "self",
                    "publicKeyJwk": jwk_from_verifying_key(self._vk),
                }
            ],
        }

        sig = self._sign_payload(payload)
        document["proof"] = {
            "type": "EcdsaSecp256k1Signature2019",
            "created": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "verificationMethod": "#master-0",
            "signatureValue": b64url_encode(sig),
        }
        return document

    def export_privkey_hex(self) -> str:
        # ecdsa SigningKey exports raw 32-byte string via to_string()
        return self._sk.to_string().hex()

    def create_token_metadata(
        self,
        did: str,
        policy_id: Optional[str] = None,
        collection: Optional[str] = None,
        vc_url: Optional[str] = None,
        *,
        did_name: str = "Token-Identity",
        vc_name: str = "Verification-Credential",
        extra_files: Optional[list[dict]] = None,
    ) -> Dict[str, Any]:
        """Create 725 metadata. Provide policy_id and optional overrides for labels and files.

        - did: DID id string (did:prism:...)
        - policy_id: collection policy id for on-chain grouping
        - collection: collection name; defaults to self.token_identity.collection_name
        - vc_url: optional URL pointing to the verifiable credential JSON
        - did_name: label for the DID entry in files[]
        - vc_name: label for the VC entry in files[] (if vc_url present)
        - extra_files: list of additional file dicts {src, name, mediaType}
        """
        pol = policy_id or self.token_identity.policy_id
        if not pol:
            raise ValueError("policy_id is required to build 725 metadata")
        coll = collection or self.token_identity.collection_name

        md: Dict[str, Any] = {
            "725": {
                "version": "1.0",
                pol: {
                    coll: {
                        "type": "JsonWebKey2020",
                        "files": [
                            {
                                "src": did,
                                "name": did_name,
                                "mediaType": "application/ld+json",
                            }
                        ],
                        "@context": "https://www.w3.org/ns/did/v1",
                    }
                },
            }
        }
        if vc_url:
            md["725"][pol][coll]["files"].append({
                "src": vc_url,
                "name": vc_name,
                "mediaType": "application/vc+json",
            })
        if extra_files:
            for f in extra_files:
                try:
                    src = f.get("src")
                    name = f.get("name")
                    mt = f.get("mediaType")
                    if src and name and mt:
                        md["725"][pol][coll]["files"].append({"src": src, "name": name, "mediaType": mt})
                except Exception:
                    pass

        sig = self._sign_metadata_generic(md)
        md["725"][pol][coll]["proof"] = {
            "type": "EcdsaSecp256k1Signature2019",
            "created": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "verificationMethod": f"{did}#master-0",
            "signatureValue": b64url_encode(sig),
        }
        return md

    def verify_did_document(self, document: Dict[str, Any]) -> bool:
        try:
            sig_b64 = document["proof"]["signatureValue"]
            sig = b64url_decode(sig_b64)
            msg = json.dumps(document["payload"], sort_keys=True).encode()
            valid = verify_sig_secp256k1(self._vk, msg, sig)
            expected_policy = self.token_identity.policy_id
            if expected_policy is None:
                policy_ok = True
            else:
                policy_ok = document["payload"].get("policyID") == expected_policy
            if self.token_identity.asset_name is not None:
                asset_ok = document["payload"].get("assetName") == self.token_identity.asset_name
            else:
                asset_ok = True
            return bool(valid and policy_ok and asset_ok)
        except Exception:
            return False

    def verify_metadata(self, metadata: Dict[str, Any], did: str) -> bool:
        try:
            # Locate policy/collection keys dynamically
            top = metadata.get("725", {})
            policy_keys = [k for k in top.keys() if k != "version"]
            if not policy_keys:
                return False
            pol = policy_keys[0]
            coll_keys = list(top[pol].keys())
            if not coll_keys:
                return False
            coll = coll_keys[0]
            md_copy = json.loads(json.dumps(metadata))
            proof = md_copy["725"][pol][coll]["proof"]
            del md_copy["725"][pol][coll]["proof"]
            sig = b64url_decode(proof["signatureValue"])
            msg = json.dumps(md_copy, sort_keys=True).encode()
            valid = verify_sig_secp256k1(self._vk, msg, sig)
            first_file = metadata["725"][pol][coll]["files"][0]
            src = first_file.get("src")
            src_ok = src == did
            return bool(valid and src_ok)
        except Exception:
            return False

    # Internal helpers
    def _sign_payload(self, payload: dict) -> bytes:
        msg = json.dumps(payload, sort_keys=True).encode()
        return sign_det_secp256k1(self._sk, msg)

    def _sign_metadata_generic(self, metadata: dict) -> bytes:
        md_copy = json.loads(json.dumps(metadata))
        # Remove any nested 'proof' objects before signing
        top = md_copy.get("725", {})
        for pol, colls in list(top.items()):
            if pol == "version":
                continue
            for coll, obj in list(colls.items()):
                if isinstance(obj, dict) and "proof" in obj:
                    del obj["proof"]
        msg = json.dumps(md_copy, sort_keys=True).encode()
        return sign_det_secp256k1(self._sk, msg)

    def _generate_did_suffix(self) -> str:
        # Company-wide DID: derive suffix from collection/company name only
        identifier = f"{self.token_identity.collection_name}"
        return hashlib.sha256(identifier.encode()).hexdigest()

    # VC for assets/projects signed by the company DID key
    def create_company_vc(
        self,
        subject_did: str,
        *,
        policy_id: Optional[str] = None,
        asset_name: Optional[str] = None,
        rwa_details: Optional[dict] = None,
        label: Optional[str] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        vc = {
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": ["VerifiableCredential", "ProjectAssetVerification"],
            "issuer": subject_did,  # issuer is the company DID
            "issuanceDate": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "credentialSubject": {
                "id": subject_did,
            },
        }
        if label:
            vc["name"] = label
        if policy_id:
            vc["credentialSubject"]["policyID"] = policy_id
        if asset_name:
            vc["credentialSubject"]["assetName"] = asset_name
        if rwa_details:
            vc["credentialSubject"]["rwaDetails"] = rwa_details

        # Merge any extra fields before signing so proof covers them
        if extra and isinstance(extra, dict):
            try:
                for k, v in extra.items():
                    vc[k] = v
            except Exception:
                pass
        msg = json.dumps(vc, sort_keys=True).encode()
        sig = sign_det_secp256k1(self._sk, msg)
        vc["proof"] = {
            "type": "EcdsaSecp256k1Signature2019",
            "verificationMethod": f"{subject_did}#master-0",
            "jws": b64url_encode(sig),
        }
        return vc
