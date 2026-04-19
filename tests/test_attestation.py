"""Unit tests for token_identity.attestation module."""
import json
import pytest
from token_identity.attestation import (
    VerifierKey,
    create_verifier_attestation,
    create_verifier_vc,
)
from token_identity.crypto import b64url_decode, verify_sig_secp256k1
from ecdsa import VerifyingKey, SECP256k1


@pytest.fixture
def verifier():
    """Create a verifier with deterministic key."""
    # Use a known private key for deterministic testing
    privkey_hex = "a" * 64  # 32 bytes of 0xaa
    return VerifierKey(privkey_hex=privkey_hex, name="TestVerifier")


@pytest.fixture
def random_verifier():
    """Create a verifier with random key."""
    return VerifierKey(name="RandomVerifier")


class TestVerifierKey:
    """Tests for VerifierKey class."""

    def test_init_with_privkey(self, verifier):
        assert verifier._sk is not None
        assert verifier._vk is not None

    def test_init_random(self, random_verifier):
        assert random_verifier._sk is not None
        assert random_verifier._vk is not None

    def test_did_format(self, verifier):
        assert verifier.did.startswith("did:prism:")
        suffix = verifier.did.split(":")[-1]
        assert len(suffix) == 64  # SHA256 hex

    def test_did_deterministic(self):
        privkey = "b" * 64
        v1 = VerifierKey(privkey_hex=privkey)
        v2 = VerifierKey(privkey_hex=privkey)
        assert v1.did == v2.did

    def test_name_stored(self, verifier):
        assert verifier.name == "TestVerifier"

    def test_jwk_structure(self, verifier):
        jwk = verifier.jwk()
        assert jwk["kty"] == "EC"
        assert jwk["crv"] == "secp256k1"
        assert "x" in jwk
        assert "y" in jwk

    def test_sign_produces_valid_signature(self, verifier):
        message = b"test message"
        signature = verifier.sign(message)
        assert len(signature) == 64  # r + s

    def test_sign_deterministic(self, verifier):
        message = b"test message"
        sig1 = verifier.sign(message)
        sig2 = verifier.sign(message)
        assert sig1 == sig2


class TestCreateVerifierAttestation:
    """Tests for verifier attestation creation."""

    def test_attestation_structure(self, verifier):
        att = create_verifier_attestation(verifier, "did:prism:project123", "policy456")
        assert att["type"] == "VerifierAttestation"
        assert att["verifier"] == verifier.did
        assert att["about"] == "did:prism:project123"
        assert att["policyID"] == "policy456"
        assert "verifierJwk" in att
        assert "proof" in att
        assert "created" in att

    def test_attestation_jwk_embedded(self, verifier):
        att = create_verifier_attestation(verifier, "did:prism:proj", "pol")
        jwk = att["verifierJwk"]
        assert jwk == verifier.jwk()

    def test_attestation_proof_structure(self, verifier):
        att = create_verifier_attestation(verifier, "did:prism:proj", "pol")
        proof = att["proof"]
        assert proof["type"] == "EcdsaSecp256k1Signature2019"
        assert f"{verifier.did}#master-0" in proof["verificationMethod"]
        assert "signatureValue" in proof

    def test_attestation_signature_verifiable(self, verifier):
        att = create_verifier_attestation(verifier, "did:prism:proj", "pol")

        # Reconstruct the payload that was signed
        payload = {
            "type": att["type"],
            "verifier": att["verifier"],
            "verifierJwk": att["verifierJwk"],
            "about": att["about"],
            "policyID": att["policyID"],
            "created": att["created"],
        }
        msg = json.dumps(payload, sort_keys=True).encode()
        sig = b64url_decode(att["proof"]["signatureValue"])

        assert verify_sig_secp256k1(verifier._vk, msg, sig) is True

    def test_attestation_tampered_fails_verification(self, verifier):
        att = create_verifier_attestation(verifier, "did:prism:proj", "pol")

        # Tamper with the attestation
        att["policyID"] = "tampered"

        payload = {
            "type": att["type"],
            "verifier": att["verifier"],
            "verifierJwk": att["verifierJwk"],
            "about": att["about"],
            "policyID": att["policyID"],
            "created": att["created"],
        }
        msg = json.dumps(payload, sort_keys=True).encode()
        sig = b64url_decode(att["proof"]["signatureValue"])

        assert verify_sig_secp256k1(verifier._vk, msg, sig) is False


class TestCreateVerifierVC:
    """Tests for verifier VC creation."""

    def test_vc_structure(self, verifier):
        vc = create_verifier_vc(verifier, "did:prism:project123", "policy456")
        assert "@context" in vc
        assert "type" in vc
        assert "issuer" in vc
        assert "issuanceDate" in vc
        assert "credentialSubject" in vc
        assert "proof" in vc

    def test_vc_types(self, verifier):
        vc = create_verifier_vc(verifier, "did:prism:proj", "pol")
        assert "VerifiableCredential" in vc["type"]
        assert "TokenProjectVerification" in vc["type"]

    def test_vc_issuer_is_verifier(self, verifier):
        vc = create_verifier_vc(verifier, "did:prism:proj", "pol")
        assert vc["issuer"] == verifier.did

    def test_vc_subject(self, verifier):
        vc = create_verifier_vc(verifier, "did:prism:project123", "policy456")
        subject = vc["credentialSubject"]
        assert subject["id"] == "did:prism:project123"
        assert subject["policyID"] == "policy456"

    def test_vc_proof_structure(self, verifier):
        vc = create_verifier_vc(verifier, "did:prism:proj", "pol")
        proof = vc["proof"]
        assert proof["type"] == "EcdsaSecp256k1Signature2019"
        assert "jws" in proof
        assert f"{verifier.did}#master-0" in proof["verificationMethod"]

    def test_vc_signature_verifiable(self, verifier):
        vc = create_verifier_vc(verifier, "did:prism:proj", "pol")

        # Reconstruct the VC without proof
        vc_copy = {k: v for k, v in vc.items() if k != "proof"}
        msg = json.dumps(vc_copy, sort_keys=True).encode()
        sig = b64url_decode(vc["proof"]["jws"])

        assert verify_sig_secp256k1(verifier._vk, msg, sig) is True

    def test_vc_context(self, verifier):
        vc = create_verifier_vc(verifier, "did:prism:proj", "pol")
        assert "https://www.w3.org/2018/credentials/v1" in vc["@context"]

    def test_different_verifiers_different_vcs(self):
        v1 = VerifierKey(privkey_hex="a" * 64)
        v2 = VerifierKey(privkey_hex="b" * 64)

        vc1 = create_verifier_vc(v1, "did:prism:proj", "pol")
        vc2 = create_verifier_vc(v2, "did:prism:proj", "pol")

        assert vc1["issuer"] != vc2["issuer"]
        assert vc1["proof"]["jws"] != vc2["proof"]["jws"]
