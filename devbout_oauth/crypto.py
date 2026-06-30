import base64
import hashlib
from cryptography.fernet import Fernet


def _get_fernet(encryption_key: str) -> Fernet:
    key = hashlib.sha256(encryption_key.encode()).digest()
    return Fernet(base64.urlsafe_b64encode(key))


def encrypt_token(plaintext: str, encryption_key: str) -> str:
    return _get_fernet(encryption_key).encrypt(plaintext.encode()).decode()


def decrypt_token(ciphertext: str, encryption_key: str) -> str:
    return _get_fernet(encryption_key).decrypt(ciphertext.encode()).decode()
