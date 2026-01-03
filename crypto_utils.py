"""Cryptographic utilities for hybrid encryption (RSA-2048 + AES-256-GCM)."""

import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def generate_rsa_keypair():
    """Generate RSA-2048 key pair."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key


def serialize_public_key(public_key) -> bytes:
    """Serialize public key to PEM format."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def deserialize_public_key(pem_data: bytes):
    """Deserialize public key from PEM format."""
    return serialization.load_pem_public_key(pem_data)


def generate_aes_key() -> bytes:
    """Generate a random 256-bit AES key."""
    return os.urandom(32)


def encrypt_aes_gcm(plaintext: bytes, key: bytes) -> tuple[bytes, bytes]:
    """Encrypt data using AES-256-GCM. Returns (nonce, ciphertext)."""
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce, ciphertext


def decrypt_aes_gcm(nonce: bytes, ciphertext: bytes, key: bytes) -> bytes:
    """Decrypt data using AES-256-GCM."""
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)


def encrypt_rsa(data: bytes, public_key) -> bytes:
    """Encrypt data using RSA-OAEP with SHA-256."""
    return public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def decrypt_rsa(ciphertext: bytes, private_key) -> bytes:
    """Decrypt data using RSA-OAEP with SHA-256."""
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def encrypt_message(message: str, recipient_public_key) -> dict:
    """
    Encrypt a message using hybrid encryption.
    Returns dict with encrypted AES key, nonce, and ciphertext.
    """
    aes_key = generate_aes_key()
    nonce, ciphertext = encrypt_aes_gcm(message.encode('utf-8'), aes_key)
    encrypted_aes_key = encrypt_rsa(aes_key, recipient_public_key)
    
    return {
        'encrypted_key': encrypted_aes_key,
        'nonce': nonce,
        'ciphertext': ciphertext
    }


def decrypt_message(encrypted_data: dict, private_key) -> str:
    """Decrypt a message using hybrid encryption."""
    aes_key = decrypt_rsa(encrypted_data['encrypted_key'], private_key)
    plaintext = decrypt_aes_gcm(
        encrypted_data['nonce'],
        encrypted_data['ciphertext'],
        aes_key
    )
    return plaintext.decode('utf-8')
