"""
Cryptographic operations for SecurePass
Handles key derivation (PBKDF2) and AES-GCM encryption/decryption
"""
import os
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class CryptoManager:
    """Manages encryption keys and operations"""
    
    ITERATIONS = 600000  # OWASP recommended minimum for PBKDF2-SHA256
    KEY_LENGTH = 32      # 256 bits for AES-256
    
    def __init__(self):
        self.key = None
        self.salt = None
    
    def derive_key(self, master_password: str, salt: bytes = None) -> bytes:
        """
        Derive encryption key from master password using PBKDF2
        
        Args:
            master_password: User's master password
            salt: Salt for KDF (generates new if None)
        
        Returns:
            32-byte encryption key
        """
        if salt is None:
            salt = os.urandom(32)
        
        self.salt = salt
        
        kdf = PBKDF2HMAC(
	    algorithm=hashes.SHA256(),
	    length=self.KEY_LENGTH,
	    salt=salt,
	    iterations=self.ITERATIONS,
	    backend=default_backend()
	)

        
        self.key = kdf.derive(master_password.encode('utf-8'))
        return self.key
    
    def encrypt(self, plaintext: str) -> str:
        """
        Encrypt data using AES-256-GCM
        
        Args:
            plaintext: Data to encrypt
        
        Returns:
            Base64-encoded ciphertext with nonce prepended
        """
        if not self.key:
            raise ValueError("Encryption key not initialized")
        
        # Generate random 96-bit nonce (recommended for AES-GCM)
        nonce = os.urandom(12)
        
        # Create AESGCM cipher
        aesgcm = AESGCM(self.key)
        
        # Encrypt (returns ciphertext + auth tag)
        ciphertext = aesgcm.encrypt(
            nonce,
            plaintext.encode('utf-8'),
            None  # No additional authenticated data
        )
        
        # Prepend nonce to ciphertext and encode
        encrypted_data = nonce + ciphertext
        return base64.b64encode(encrypted_data).decode('utf-8')
    
    def decrypt(self, encrypted_data: str) -> str:
        """
        Decrypt AES-256-GCM encrypted data
        
        Args:
            encrypted_data: Base64-encoded ciphertext with nonce
        
        Returns:
            Decrypted plaintext
        """
        if not self.key:
            raise ValueError("Encryption key not initialized")
        
        try:
            # Decode from base64
            encrypted_bytes = base64.b64decode(encrypted_data)
            
            # Extract nonce (first 12 bytes) and ciphertext
            nonce = encrypted_bytes[:12]
            ciphertext = encrypted_bytes[12:]
            
            # Decrypt
            aesgcm = AESGCM(self.key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            
            return plaintext.decode('utf-8')
        except Exception as e:
            raise ValueError(f"Decryption failed: {str(e)}")
    
    def get_salt_b64(self) -> str:
        """Return base64-encoded salt for storage"""
        return base64.b64encode(self.salt).decode('utf-8')
    
    def set_salt_from_b64(self, salt_b64: str):
        """Set salt from base64-encoded string"""
        self.salt = base64.b64decode(salt_b64)
