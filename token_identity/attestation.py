from __future__ import annotations

import json
import time
from typing import Dict, Any

from .crypto import (
    gen_secp256k1_keypair,
    jwk_from_verifying_key,
    sign_det_secp256k1,
    b64url_encode,
)


class VerifierKey:
    """Holds a verifier keypair and DID id string for attestations."""

    def __init__(self, privkey_hex: str | None = None, name: str = "Verifier"):
        if privkey_hex:
            from ecdsa import SigningKey, SECP256k1
            self._sk = SigningKey.from_string(bytes.fromhex(privkey_hex), curve=SECP256k1)
            self._vk = self._sk.get_verifying_key()
        else:
            self._sk, self._vk = gen_secp256k1_keypair()
        # Derive a simple DID for the verifier by hashing the public key (32+32 bytes)
        pub = self._vk.to_string("uncompressed")[1:65]
        import hashlib
        suffix = hashlib.sha256(pub).hexdigest()
        self.did = f"did:prism:{suffix}"
        self.name = name

    def jwk(self) -> Dict[str, Any]:
        return jwk_from_verifying_key(self._vk)

    def sign(self, message: bytes) -> bytes:
        return sign_det_secp256k1(self._sk, message)


def create_verifier_attestation(verifier: VerifierKey, project_did: str, policy_id: str) -> Dict[str, Any]:
    """Create a minimal verifier attestation JSON, signed by the verifier key.

    This is not a full VC; it's a compact, verifiable object binding the project DID and policy.
    """
    payload: Dict[str, Any] = {
        "type": "VerifierAttestation",
        "verifier": verifier.did,
        "verifierJwk": verifier.jwk(),
        "about": project_did,
        "policyID": policy_id,
        "created": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    msg = json.dumps(payload, sort_keys=True).encode()
    sig = verifier.sign(msg)
    att: Dict[str, Any] = {
        **payload,
        "proof": {
            "type": "EcdsaSecp256k1Signature2019",
            "verificationMethod": f"{verifier.did}#master-0",
            "signatureValue": b64url_encode(sig),
        },
    }
    return att


def create_verifier_vc(verifier: VerifierKey, project_did: str, policy_id: str) -> Dict[str, Any]:
    """Create a minimal W3C Verifiable Credential-style attestation.

    Note: This is a simplified VC-like object using ES256K proof.
    """
    vc = {
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
        ],
        "type": ["VerifiableCredential", "TokenProjectVerification"],
        "issuer": verifier.did,
        "issuanceDate": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "credentialSubject": {
            "id": project_did,
            "policyID": policy_id,
        },
    }
    msg = json.dumps(vc, sort_keys=True).encode()
    sig = verifier.sign(msg)
    vc["proof"] = {
        "type": "EcdsaSecp256k1Signature2019",
        "verificationMethod": f"{verifier.did}#master-0",
        "jws": b64url_encode(sig),
    }
    return vc
