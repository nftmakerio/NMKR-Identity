"""Unit tests for token_identity.prism_did module."""
import json
import pytest
from token_identity.models import TokenIdentity
from token_identity.prism_did import PrismDIDManager
from token_identity.crypto import b64url_decode


@pytest.fixture
def basic_identity():
    """Basic token identity for testing."""
    return TokenIdentity(
        policy_id="abc123def456",
        collection_name="TestCollection",
        asset_name=None,
        social_accounts={"twitter": ["@test"]},
        website=["https://test.com"],
    )


@pytest.fixture
def full_identity():
    """Full token identity with all fields."""
    return TokenIdentity(
        policy_id="policy123",
        collection_name="FullCollection",
        asset_name="Asset001",
        social_accounts={"twitter": ["@test"], "discord": ["testserver"]},
        website=["https://test.com", "https://docs.test.com"],
        rwa_details={"assetType": "RealEstate", "jurisdiction": "US"},
        extra_payload={"customField": "customValue"},
    )


@pytest.fixture
def manager(basic_identity):
    """PrismDIDManager with deterministic key."""
    return PrismDIDManager(basic_identity, seed=b"test-seed")


class TestPrismDIDManagerInit:
    """Tests for PrismDIDManager initialization."""

    def test_init_with_seed(self, basic_identity):
        mgr = PrismDIDManager(basic_identity, seed=b"test-seed")
        assert mgr._sk is not None
        assert mgr._vk is not None

    def test_init_with_privkey_hex(self, basic_identity):
        # Generate a key first
        mgr1 = PrismDIDManager(basic_identity, seed=b"test")
        privkey_hex = mgr1.export_privkey_hex()

        # Create new manager with that key
        mgr2 = PrismDIDManager(basic_identity, privkey_hex=privkey_hex)
        assert mgr2.export_privkey_hex() == privkey_hex

    def test_init_random_key(self, basic_identity):
        mgr1 = PrismDIDManager(basic_identity)
        mgr2 = PrismDIDManager(basic_identity)
        assert mgr1.export_privkey_hex() != mgr2.export_privkey_hex()

    def test_deterministic_key_from_seed(self, basic_identity):
        mgr1 = PrismDIDManager(basic_identity, seed=b"same-seed")
        mgr2 = PrismDIDManager(basic_identity, seed=b"same-seed")
        assert mgr1.export_privkey_hex() == mgr2.export_privkey_hex()


class TestExportPrivkey:
    """Tests for private key export."""

    def test_export_privkey_hex_format(self, manager):
        privkey = manager.export_privkey_hex()
        assert isinstance(privkey, str)
        assert len(privkey) == 64  # 32 bytes = 64 hex chars
        int(privkey, 16)  # Should be valid hex

    def test_export_privkey_deterministic(self, manager):
        key1 = manager.export_privkey_hex()
        key2 = manager.export_privkey_hex()
        assert key1 == key2


class TestCreateDIDDocument:
    """Tests for DID Document creation."""

    def test_did_document_structure(self, manager):
        doc = manager.create_did_document()
        assert "@context" in doc
        assert "id" in doc
        assert "payload" in doc
        assert "verificationMethod" in doc
        assert "proof" in doc

    def test_did_format(self, manager):
        doc = manager.create_did_document()
        did_id = doc["id"]
        assert did_id.startswith("did:prism:")
        suffix = did_id.split(":")[-1]
        assert len(suffix) == 64  # SHA256 hex

    def test_did_context(self, manager):
        doc = manager.create_did_document()
        assert "https://www.w3.org/ns/did/v1" in doc["@context"]

    def test_verification_method(self, manager):
        doc = manager.create_did_document()
        vm = doc["verificationMethod"][0]
        assert vm["id"] == "#master-0"
        assert vm["type"] == "JsonWebKey2020"
        assert vm["controller"] == "self"
        assert "publicKeyJwk" in vm

    def test_public_key_jwk_structure(self, manager):
        doc = manager.create_did_document()
        jwk = doc["verificationMethod"][0]["publicKeyJwk"]
        assert jwk["kty"] == "EC"
        assert jwk["crv"] == "secp256k1"
        assert "x" in jwk
        assert "y" in jwk

    def test_proof_structure(self, manager):
        doc = manager.create_did_document()
        proof = doc["proof"]
        assert proof["type"] == "EcdsaSecp256k1Signature2019"
        assert proof["verificationMethod"] == "#master-0"
        assert "signatureValue" in proof
        assert "created" in proof

    def test_payload_contains_identity_info(self, basic_identity):
        mgr = PrismDIDManager(basic_identity, seed=b"test")
        doc = mgr.create_did_document()
        payload = doc["payload"]
        assert payload["policyID"] == "abc123def456"
        assert payload["accounts"] == {"twitter": ["@test"]}
        assert payload["website"] == ["https://test.com"]
        assert "date" in payload

    def test_payload_with_rwa_details(self, full_identity):
        mgr = PrismDIDManager(full_identity, seed=b"test")
        doc = mgr.create_did_document()
        payload = doc["payload"]
        assert "rwaDetails" in payload
        assert payload["rwaDetails"]["assetType"] == "RealEstate"

    def test_payload_with_extra_fields(self, full_identity):
        mgr = PrismDIDManager(full_identity, seed=b"test")
        doc = mgr.create_did_document()
        payload = doc["payload"]
        assert payload["customField"] == "customValue"

    def test_did_suffix_from_collection_name(self, basic_identity):
        import hashlib
        mgr = PrismDIDManager(basic_identity, seed=b"test")
        doc = mgr.create_did_document()
        expected_suffix = hashlib.sha256("TestCollection".encode()).hexdigest()
        assert doc["id"] == f"did:prism:{expected_suffix}"


class TestVerifyDIDDocument:
    """Tests for DID Document verification."""

    def test_verify_valid_document(self, manager):
        doc = manager.create_did_document()
        assert manager.verify_did_document(doc) is True

    def test_verify_tampered_payload_fails(self, manager):
        doc = manager.create_did_document()
        doc["payload"]["policyID"] = "tampered"
        assert manager.verify_did_document(doc) is False

    def test_verify_tampered_signature_fails(self, manager):
        doc = manager.create_did_document()
        sig = doc["proof"]["signatureValue"]
        # Corrupt signature
        doc["proof"]["signatureValue"] = sig[:-4] + "XXXX"
        assert manager.verify_did_document(doc) is False

    def test_verify_wrong_key_fails(self, basic_identity):
        mgr1 = PrismDIDManager(basic_identity, seed=b"key1")
        mgr2 = PrismDIDManager(basic_identity, seed=b"key2")
        doc = mgr1.create_did_document()
        assert mgr2.verify_did_document(doc) is False

    def test_verify_missing_proof_fails(self, manager):
        doc = manager.create_did_document()
        del doc["proof"]
        assert manager.verify_did_document(doc) is False


class TestCreateCompanyVC:
    """Tests for Verifiable Credential creation."""

    def test_vc_structure(self, manager):
        doc = manager.create_did_document()
        vc = manager.create_company_vc(doc["id"], policy_id="pol123")
        assert "@context" in vc
        assert "type" in vc
        assert "issuer" in vc
        assert "issuanceDate" in vc
        assert "credentialSubject" in vc
        assert "proof" in vc

    def test_vc_types(self, manager):
        doc = manager.create_did_document()
        vc = manager.create_company_vc(doc["id"])
        assert "VerifiableCredential" in vc["type"]
        assert "ProjectAssetVerification" in vc["type"]

    def test_vc_issuer_is_subject(self, manager):
        doc = manager.create_did_document()
        vc = manager.create_company_vc(doc["id"])
        assert vc["issuer"] == doc["id"]
        assert vc["credentialSubject"]["id"] == doc["id"]

    def test_vc_with_policy_id(self, manager):
        doc = manager.create_did_document()
        vc = manager.create_company_vc(doc["id"], policy_id="testpolicy")
        assert vc["credentialSubject"]["policyID"] == "testpolicy"

    def test_vc_with_asset_name(self, manager):
        doc = manager.create_did_document()
        vc = manager.create_company_vc(doc["id"], asset_name="Asset001")
        assert vc["credentialSubject"]["assetName"] == "Asset001"

    def test_vc_with_rwa_details(self, manager):
        doc = manager.create_did_document()
        rwa = {"assetType": "Bond", "jurisdiction": "EU"}
        vc = manager.create_company_vc(doc["id"], rwa_details=rwa)
        assert vc["credentialSubject"]["rwaDetails"] == rwa

    def test_vc_with_label(self, manager):
        doc = manager.create_did_document()
        vc = manager.create_company_vc(doc["id"], label="Test Credential")
        assert vc["name"] == "Test Credential"

    def test_vc_with_extra_fields(self, manager):
        doc = manager.create_did_document()
        extra = {"customField": "value", "anotherField": 123}
        vc = manager.create_company_vc(doc["id"], extra=extra)
        assert vc["customField"] == "value"
        assert vc["anotherField"] == 123

    def test_vc_proof_structure(self, manager):
        doc = manager.create_did_document()
        vc = manager.create_company_vc(doc["id"])
        proof = vc["proof"]
        assert proof["type"] == "EcdsaSecp256k1Signature2019"
        assert "jws" in proof
        assert f"{doc['id']}#master-0" in proof["verificationMethod"]


class TestCreateTokenMetadata:
    """Tests for Cardano 725 metadata creation."""

    def test_metadata_structure(self, basic_identity):
        mgr = PrismDIDManager(basic_identity, seed=b"test")
        doc = mgr.create_did_document()
        md = mgr.create_token_metadata(doc["id"], policy_id="pol123", collection="Col")
        assert "725" in md
        assert md["725"]["version"] == "1.0"
        assert "pol123" in md["725"]
        assert "Col" in md["725"]["pol123"]

    def test_metadata_files_array(self, basic_identity):
        mgr = PrismDIDManager(basic_identity, seed=b"test")
        doc = mgr.create_did_document()
        md = mgr.create_token_metadata(doc["id"], policy_id="pol123", collection="Col")
        files = md["725"]["pol123"]["Col"]["files"]
        assert len(files) >= 1
        assert files[0]["src"] == doc["id"]
        assert files[0]["mediaType"] == "application/ld+json"

    def test_metadata_with_vc_url(self, basic_identity):
        mgr = PrismDIDManager(basic_identity, seed=b"test")
        doc = mgr.create_did_document()
        vc_url = "https://example.com/vc/123"
        md = mgr.create_token_metadata(doc["id"], policy_id="pol123", collection="Col", vc_url=vc_url)
        files = md["725"]["pol123"]["Col"]["files"]
        assert len(files) == 2
        assert files[1]["src"] == vc_url
        assert files[1]["mediaType"] == "application/vc+json"

    def test_metadata_proof(self, basic_identity):
        mgr = PrismDIDManager(basic_identity, seed=b"test")
        doc = mgr.create_did_document()
        md = mgr.create_token_metadata(doc["id"], policy_id="pol123", collection="Col")
        proof = md["725"]["pol123"]["Col"]["proof"]
        assert proof["type"] == "EcdsaSecp256k1Signature2019"
        assert "signatureValue" in proof

    def test_metadata_requires_policy_id(self, basic_identity):
        identity = TokenIdentity(
            policy_id=None,
            collection_name="Test",
            asset_name=None,
            social_accounts={},
            website=[],
        )
        mgr = PrismDIDManager(identity, seed=b"test")
        doc = mgr.create_did_document()
        with pytest.raises(ValueError, match="policy_id is required"):
            mgr.create_token_metadata(doc["id"])

    def test_metadata_uses_identity_defaults(self, basic_identity):
        mgr = PrismDIDManager(basic_identity, seed=b"test")
        doc = mgr.create_did_document()
        md = mgr.create_token_metadata(doc["id"])
        # Should use policy_id and collection_name from identity
        assert "abc123def456" in md["725"]
        assert "TestCollection" in md["725"]["abc123def456"]


class TestVerifyMetadata:
    """Tests for metadata verification."""

    def test_verify_valid_metadata(self, basic_identity):
        mgr = PrismDIDManager(basic_identity, seed=b"test")
        doc = mgr.create_did_document()
        md = mgr.create_token_metadata(doc["id"])
        assert mgr.verify_metadata(md, doc["id"]) is True

    def test_verify_tampered_metadata_fails(self, basic_identity):
        mgr = PrismDIDManager(basic_identity, seed=b"test")
        doc = mgr.create_did_document()
        md = mgr.create_token_metadata(doc["id"])
        # Find the policy key (skip "version")
        policy_keys = [k for k in md["725"].keys() if k != "version"]
        pol = policy_keys[0]
        coll = list(md["725"][pol].keys())[0]
        # Tamper with the file name
        md["725"][pol][coll]["files"][0]["name"] = "tampered"
        assert mgr.verify_metadata(md, doc["id"]) is False

    def test_verify_wrong_did_fails(self, basic_identity):
        mgr = PrismDIDManager(basic_identity, seed=b"test")
        doc = mgr.create_did_document()
        md = mgr.create_token_metadata(doc["id"])
        assert mgr.verify_metadata(md, "did:prism:wrongdid") is False
