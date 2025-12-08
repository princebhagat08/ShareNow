"""
Cryptographic Engine for Secure File Sharing
Implements:
- Diffie-Hellman Key Exchange
- AES-256 Encryption/Decryption
"""

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import base64


class DiffieHellmanManager:
    """Manages Diffie-Hellman key exchange"""
    
    # RFC 3526 2048-bit MODP Group
    PARAMETERS = dh.DHParameterNumbers(
        p=int(
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
            "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
            "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
            "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
            "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
            "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
            "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
            "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
            "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
            "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
            "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16
        ),
        g=2
    ).parameters(default_backend())
    
    def __init__(self):
        self.private_key = None
        self.public_key = None
        self.shared_secret = None
        
    def generate_keys(self):
        """Generate a new DH key pair"""
        self.private_key = self.PARAMETERS.generate_private_key()
        self.public_key = self.private_key.public_key()
        return self.get_public_key_bytes()
    
    def get_public_key_bytes(self):
        """Export public key as PEM format"""
        if not self.public_key:
            raise ValueError("No public key generated")
        
        pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem.decode('utf-8')
    
    def load_peer_public_key(self, peer_public_key_pem):
        """Load peer's public key from PEM format"""
        peer_public_key = serialization.load_pem_public_key(
            peer_public_key_pem.encode('utf-8'),
            backend=default_backend()
        )
        return peer_public_key
    
    def derive_shared_secret(self, peer_public_key_pem):
        """Derive shared secret from peer's public key"""
        if not self.private_key:
            raise ValueError("No private key available")
        
        peer_public_key = self.load_peer_public_key(peer_public_key_pem)
        shared_key = self.private_key.exchange(peer_public_key)
        
        # Derive a 256-bit key using HKDF
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # 256 bits for AES-256
            salt=None,
            info=b'file-sharing-key',
            backend=default_backend()
        ).derive(shared_key)
        
        self.shared_secret = derived_key
        return base64.b64encode(derived_key).decode('utf-8')


class AESCipher:
    """AES-256 encryption/decryption in GCM mode"""
    
    @staticmethod
    def encrypt(data, key_b64):
        """
        Encrypt data using AES-256-GCM
        Returns: base64(iv + tag + ciphertext)
        """
        key = base64.b64decode(key_b64)
        
        # Generate random IV (12 bytes for GCM)
        iv = os.urandom(12)
        
        # Create cipher
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        
        # Encrypt
        ciphertext = encryptor.update(data) + encryptor.finalize()
        
        # Combine IV + Tag + Ciphertext
        encrypted_data = iv + encryptor.tag + ciphertext
        
        return base64.b64encode(encrypted_data).decode('utf-8')
    
    @staticmethod
    def decrypt(encrypted_data_b64, key_b64):
        """
        Decrypt data using AES-256-GCM
        Expects: base64(iv + tag + ciphertext)
        """
        key = base64.b64decode(key_b64)
        encrypted_data = base64.b64decode(encrypted_data_b64)
        
        # Extract components
        iv = encrypted_data[:12]
        tag = encrypted_data[12:28]
        ciphertext = encrypted_data[28:]
        
        # Create cipher
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(iv, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        
        # Decrypt
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        return plaintext


# Session storage (in-memory for demo purposes)
class SessionManager:
    """Manages user sessions and their DH instances"""
    
    def __init__(self):
        self.sessions = {}
    
    def create_session(self, session_id):
        """Create a new DH session"""
        if session_id not in self.sessions:
            self.sessions[session_id] = DiffieHellmanManager()
        return self.sessions[session_id]
    
    def get_session(self, session_id):
        """Get existing session"""
        return self.sessions.get(session_id)
    
    def delete_session(self, session_id):
        """Delete a session"""
        if session_id in self.sessions:
            del self.sessions[session_id]
