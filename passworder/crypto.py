from os import urandom

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from passworder.config import settings


def derive_key(master_password: str, salt: bytes) -> bytes:
    """
    Derive a symmetric encryption key from the master password and salt.

    :param master_password: User-provided master password
    :param salt: Random salt
    :return: Derived key bytes
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=settings.kdf_iterations
    )
    return kdf.derive(master_password.encode())


def encrypt(plaintext: bytes, key: bytes) -> tuple[bytes, bytes, bytes]:
    """
    Encrypt data using AES-GCM.

    :param plaintext: Data to encrypt
    :param key: Symmetric key
    :return: tuple of (salt, iv, ciphertext)
    """
    salt = urandom(settings.kdf_salt_size)
    iv = urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(iv, plaintext, None)
    return salt, iv, ciphertext


def decrypt(
    salt: bytes,
    iv: bytes,
    ciphertext: bytes,
    master_password: str
) -> bytes:
    """
    Decrypt data encrypted with AES-GCM.

    :param salt: Salt used for key derivation
    :param iv: Initialization vector
    :param ciphertext: Encrypted data
    :param master_password: User's master password
    :return: Decrypted plaintext
    """
    key = derive_key(master_password, salt)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(iv, ciphertext, None)
