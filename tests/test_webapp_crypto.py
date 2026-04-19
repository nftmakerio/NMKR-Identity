"""Unit tests for webapp.crypto_utils module."""
import pytest
from webapp.crypto_utils import encrypt_with_passphrase, decrypt_with_passphrase
from cryptography.fernet import InvalidToken


class TestEncryptDecrypt:
    """Tests for passphrase-based encryption/decryption."""

    def test_encrypt_returns_string(self):
        result = encrypt_with_passphrase("password", b"secret data")
        assert isinstance(result, str)

    def test_decrypt_returns_bytes(self):
        encrypted = encrypt_with_passphrase("password", b"secret data")
        result = decrypt_with_passphrase("password", encrypted)
        assert isinstance(result, bytes)

    def test_roundtrip_simple(self):
        passphrase = "my-secret-passphrase"
        plaintext = b"Hello, World!"
        encrypted = encrypt_with_passphrase(passphrase, plaintext)
        decrypted = decrypt_with_passphrase(passphrase, encrypted)
        assert decrypted == plaintext

    def test_roundtrip_binary_data(self):
        passphrase = "pass123"
        plaintext = bytes(range(256))
        encrypted = encrypt_with_passphrase(passphrase, plaintext)
        decrypted = decrypt_with_passphrase(passphrase, encrypted)
        assert decrypted == plaintext

    def test_roundtrip_empty_data(self):
        passphrase = "pass"
        plaintext = b""
        encrypted = encrypt_with_passphrase(passphrase, plaintext)
        decrypted = decrypt_with_passphrase(passphrase, encrypted)
        assert decrypted == plaintext

    def test_roundtrip_large_data(self):
        passphrase = "pass"
        plaintext = b"x" * 100000
        encrypted = encrypt_with_passphrase(passphrase, plaintext)
        decrypted = decrypt_with_passphrase(passphrase, encrypted)
        assert decrypted == plaintext

    def test_wrong_passphrase_fails(self):
        encrypted = encrypt_with_passphrase("correct", b"secret")
        with pytest.raises(InvalidToken):
            decrypt_with_passphrase("wrong", encrypted)

    def test_empty_passphrase(self):
        passphrase = ""
        plaintext = b"data"
        encrypted = encrypt_with_passphrase(passphrase, plaintext)
        decrypted = decrypt_with_passphrase(passphrase, encrypted)
        assert decrypted == plaintext

    def test_unicode_passphrase(self):
        passphrase = "пароль密码🔐"
        plaintext = b"secret data"
        encrypted = encrypt_with_passphrase(passphrase, plaintext)
        decrypted = decrypt_with_passphrase(passphrase, encrypted)
        assert decrypted == plaintext

    def test_different_encryptions_different_output(self):
        # Due to random salt, same plaintext produces different ciphertext
        passphrase = "pass"
        plaintext = b"data"
        enc1 = encrypt_with_passphrase(passphrase, plaintext)
        enc2 = encrypt_with_passphrase(passphrase, plaintext)
        assert enc1 != enc2

    def test_both_decrypt_to_same_plaintext(self):
        passphrase = "pass"
        plaintext = b"data"
        enc1 = encrypt_with_passphrase(passphrase, plaintext)
        enc2 = encrypt_with_passphrase(passphrase, plaintext)
        dec1 = decrypt_with_passphrase(passphrase, enc1)
        dec2 = decrypt_with_passphrase(passphrase, enc2)
        assert dec1 == dec2 == plaintext

    def test_corrupted_ciphertext_fails(self):
        encrypted = encrypt_with_passphrase("pass", b"data")
        # Corrupt the ciphertext
        import base64
        data = bytearray(base64.urlsafe_b64decode(encrypted))
        data[20] ^= 0xFF
        corrupted = base64.urlsafe_b64encode(bytes(data)).decode()
        with pytest.raises(InvalidToken):
            decrypt_with_passphrase("pass", corrupted)

    def test_truncated_ciphertext_fails(self):
        encrypted = encrypt_with_passphrase("pass", b"data")
        truncated = encrypted[:20]
        with pytest.raises(Exception):  # Various exceptions possible
            decrypt_with_passphrase("pass", truncated)


class TestKeyDerivation:
    """Tests for key derivation properties."""

    def test_same_passphrase_same_salt_same_key(self):
        # Internal test - verify PBKDF2 is deterministic with same salt
        from webapp.crypto_utils import _derive_key
        salt = b"fixed_salt_16bb"
        key1 = _derive_key("password", salt)
        key2 = _derive_key("password", salt)
        assert key1 == key2

    def test_different_passphrase_different_key(self):
        from webapp.crypto_utils import _derive_key
        salt = b"fixed_salt_16bb"
        key1 = _derive_key("password1", salt)
        key2 = _derive_key("password2", salt)
        assert key1 != key2

    def test_different_salt_different_key(self):
        from webapp.crypto_utils import _derive_key
        key1 = _derive_key("password", b"salt_one_16byte")
        key2 = _derive_key("password", b"salt_two_16byte")
        assert key1 != key2
