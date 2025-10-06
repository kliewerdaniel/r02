import os
from typing import Optional, Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import oqs
from .hsm.abstract_store import KeyStoreABC
from .config.crypto_config import get_kem_algorithm, get_signature_algorithm

class PQCKEM:
    def __init__(self, keystore: Optional[KeyStoreABC] = None, client_id: Optional[str] = None):
        self.kem = oqs.KeyEncapsulation(get_kem_algorithm())
        self.public_bytes = None
        self.keystore = keystore
        self.client_id = client_id

    def generate_keypair(self) -> bytes:
        self.public_bytes = self.kem.generate_keypair()
        if self.keystore and self.client_id:
            try:
                # Export the secret key and store in keystore for persistence
                secret_key = self.kem.export_secret_key()
                self.keystore.store_private_key(self.client_id, 'kem', secret_key)
            except AttributeError:
                # If export_secret_key not available, skip HSM storage
                pass
        return self.public_bytes

    def encapsulate(self, peer_pub: bytes) -> Tuple[bytes, bytes]:
        if len(peer_pub) != self.kem.details["public_key_length"]:
            raise ValueError("Invalid peer public key length")
        ciphertext, shared_secret = self.kem.encap_secret(peer_pub)
        return ciphertext, shared_secret

    def decapsulate(self, ciphertext: bytes) -> bytes:
        shared_secret = self.kem.decap_secret(ciphertext)
        return shared_secret

    def export_public(self) -> bytes:
        return self.public_bytes

class PQCSign:
    def __init__(self, keystore: Optional[KeyStoreABC] = None, client_id: Optional[str] = None):
        self.sig = oqs.Signature(get_signature_algorithm())
        self.public_bytes = None
        self._private_key = None
        self.keystore = keystore
        self.client_id = client_id

    def generate_keypair(self) -> bytes:
        self.public_bytes, self._private_key = self.sig.generate_keypair()
        if self.keystore and self.client_id:
            self.keystore.store_private_key(self.client_id, 'sign', self._private_key)
        return self.public_bytes

    def sign(self, message: bytes) -> bytes:
        signature = self.sig.sign(message)
        return signature

    @staticmethod
    def verify(pub: bytes, message: bytes, sig: bytes) -> bool:
        with oqs.Signature(get_signature_algorithm()) as verifier:
            is_valid = verifier.verify(message, sig, pub)
            return is_valid

def derive_session_key(shared_secret: bytes, qkd_key: Optional[bytes], qrng: Optional[bytes], client_nonce: bytes, server_nonce: bytes) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"QASPv0.1" + client_nonce + server_nonce,
    )
    key_material = shared_secret + (qkd_key or b'') + (qrng or b'')
    session_key = hkdf.derive(key_material)
    return session_key

def aead_encrypt(key: bytes, plaintext: bytes, aad: bytes) -> Tuple[bytes, bytes]:
    try:
        aead = ChaCha20Poly1305(key)
        nonce = os.urandom(12)  # ChaCha20Poly1305 uses 96-bit nonce
    except Exception:
        aead = AESGCM(key)
        nonce = os.urandom(12)  # AES-GCM uses 96-bit nonce
    ciphertext = aead.encrypt(nonce, plaintext, aad)
    return nonce, ciphertext

def aead_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    try:
        aead = ChaCha20Poly1305(key)
    except Exception:
        aead = AESGCM(key)
    plaintext = aead.decrypt(nonce, ciphertext, aad)
    return plaintext
