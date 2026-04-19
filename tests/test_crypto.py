"""Unit tests for token_identity.crypto module."""
import pytest
from token_identity.crypto import (
    b64url_encode,
    b64url_decode,
    sha256,
    gen_secp256k1_keypair,
    jwk_from_verifying_key,
    sign_det_secp256k1,
    verify_sig_secp256k1,
)


class TestBase64Url:
    """Tests for base64url encoding/decoding."""

    def test_encode_simple(self):
        data = b"hello world"
        encoded = b64url_encode(data)
        assert isinstance(encoded, str)
        assert "=" not in encoded  # No padding

    def test_decode_simple(self):
        data = b"hello world"
        encoded = b64url_encode(data)
        decoded = b64url_decode(encoded)
        assert decoded == data

    def test_roundtrip_binary(self):
        data = bytes(range(256))
        encoded = b64url_encode(data)
        decoded = b64url_decode(encoded)
        assert decoded == data

    def test_decode_with_padding(self):
        # Test that decoder handles missing padding
        encoded = b64url_encode(b"test")
        decoded = b64url_decode(encoded)
        assert decoded == b"test"

    def test_empty_data(self):
        encoded = b64url_encode(b"")
        decoded = b64url_decode(encoded)
        assert decoded == b""


class TestSha256:
    """Tests for SHA256 hashing."""

    def test_known_hash(self):
        result = sha256(b"hello")
        assert len(result) == 32
        expected = bytes.fromhex("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
        assert result == expected

    def test_empty_input(self):
        result = sha256(b"")
        assert len(result) == 32
        expected = bytes.fromhex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        assert result == expected

    def test_deterministic(self):
        result1 = sha256(b"test data")
        result2 = sha256(b"test data")
        assert result1 == result2


class TestSecp256k1Keypair:
    """Tests for secp256k1 keypair generation."""

    def test_generate_random_keypair(self):
        sk, vk = gen_secp256k1_keypair()
        assert sk is not None
        assert vk is not None
        assert len(sk.to_string()) == 32  # Private key is 32 bytes

    def test_generate_deterministic_keypair(self):
        seed = b"test seed for deterministic key"
        sk1, vk1 = gen_secp256k1_keypair(seed=seed)
        sk2, vk2 = gen_secp256k1_keypair(seed=seed)
        assert sk1.to_string() == sk2.to_string()
        assert vk1.to_string() == vk2.to_string()

    def test_different_seeds_different_keys(self):
        sk1, _ = gen_secp256k1_keypair(seed=b"seed1")
        sk2, _ = gen_secp256k1_keypair(seed=b"seed2")
        assert sk1.to_string() != sk2.to_string()

    def test_random_keys_are_unique(self):
        sk1, _ = gen_secp256k1_keypair()
        sk2, _ = gen_secp256k1_keypair()
        assert sk1.to_string() != sk2.to_string()


class TestJwkFromVerifyingKey:
    """Tests for JWK generation from public key."""

    def test_jwk_structure(self):
        _, vk = gen_secp256k1_keypair(seed=b"test")
        jwk = jwk_from_verifying_key(vk)
        assert jwk["kty"] == "EC"
        assert jwk["crv"] == "secp256k1"
        assert "x" in jwk
        assert "y" in jwk

    def test_jwk_coordinates_valid(self):
        _, vk = gen_secp256k1_keypair(seed=b"test")
        jwk = jwk_from_verifying_key(vk)
        x = b64url_decode(jwk["x"])
        y = b64url_decode(jwk["y"])
        assert len(x) == 32
        assert len(y) == 32

    def test_jwk_deterministic(self):
        _, vk = gen_secp256k1_keypair(seed=b"test")
        jwk1 = jwk_from_verifying_key(vk)
        jwk2 = jwk_from_verifying_key(vk)
        assert jwk1 == jwk2


class TestSigningAndVerification:
    """Tests for ECDSA signing and verification."""

    def test_sign_and_verify(self):
        sk, vk = gen_secp256k1_keypair(seed=b"test")
        message = b"test message"
        signature = sign_det_secp256k1(sk, message)
        assert len(signature) == 64  # r (32) + s (32)
        assert verify_sig_secp256k1(vk, message, signature) is True

    def test_deterministic_signing(self):
        sk, _ = gen_secp256k1_keypair(seed=b"test")
        message = b"test message"
        sig1 = sign_det_secp256k1(sk, message)
        sig2 = sign_det_secp256k1(sk, message)
        assert sig1 == sig2

    def test_different_messages_different_signatures(self):
        sk, _ = gen_secp256k1_keypair(seed=b"test")
        sig1 = sign_det_secp256k1(sk, b"message1")
        sig2 = sign_det_secp256k1(sk, b"message2")
        assert sig1 != sig2

    def test_verify_wrong_message_fails(self):
        sk, vk = gen_secp256k1_keypair(seed=b"test")
        signature = sign_det_secp256k1(sk, b"original message")
        result = verify_sig_secp256k1(vk, b"wrong message", signature)
        assert result is False

    def test_verify_wrong_key_fails(self):
        sk1, _ = gen_secp256k1_keypair(seed=b"key1")
        _, vk2 = gen_secp256k1_keypair(seed=b"key2")
        message = b"test message"
        signature = sign_det_secp256k1(sk1, message)
        result = verify_sig_secp256k1(vk2, message, signature)
        assert result is False

    def test_verify_corrupted_signature_fails(self):
        sk, vk = gen_secp256k1_keypair(seed=b"test")
        message = b"test message"
        signature = bytearray(sign_det_secp256k1(sk, message))
        signature[0] ^= 0xFF  # Corrupt first byte
        result = verify_sig_secp256k1(vk, message, bytes(signature))
        assert result is False

    def test_empty_message(self):
        sk, vk = gen_secp256k1_keypair(seed=b"test")
        message = b""
        signature = sign_det_secp256k1(sk, message)
        assert verify_sig_secp256k1(vk, message, signature) is True

    def test_large_message(self):
        sk, vk = gen_secp256k1_keypair(seed=b"test")
        message = b"x" * 100000
        signature = sign_det_secp256k1(sk, message)
        assert verify_sig_secp256k1(vk, message, signature) is True
