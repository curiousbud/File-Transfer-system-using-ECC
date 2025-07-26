"""
Secure Key Storage Module

This module handles secure storage and retrieval of ECC private keys
using password-based encryption and secure key derivation.
"""

import os
import base64
import secrets
from typing import Tuple, Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec

from .ecc_manager import ECCManager


class SecureKeyStorage:
    """
    Handles secure storage of ECC private keys with password-based encryption
    """
    
    # Security parameters
    PBKDF2_ITERATIONS = 100000  # 100,000 iterations for key derivation
    SALT_SIZE = 32  # 256-bit salt
    KEY_SIZE = 32   # 256-bit encryption key
    NONCE_SIZE = 16  # 128-bit nonce for AES-CTR
    
    def __init__(self):
        self.backend = default_backend()
    
    def generate_salt(self) -> bytes:
        """
        Generate cryptographically secure random salt
        
        Returns:
            bytes: Random salt
        """
        return secrets.token_bytes(self.SALT_SIZE)
    
    def derive_key_from_password(self, password: str, salt: bytes) -> bytes:
        """
        Derive encryption key from password using PBKDF2
        
        Args:
            password: User password
            salt: Random salt for key derivation
            
        Returns:
            bytes: Derived encryption key
        """
        password_bytes = password.encode('utf-8')
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.KEY_SIZE,
            salt=salt,
            iterations=self.PBKDF2_ITERATIONS,
            backend=self.backend
        )
        
        return kdf.derive(password_bytes)
    
    def encrypt_private_key(self, private_key_pem: bytes, password: str) -> dict:
        """
        Encrypt private key with password-based encryption
        
        Args:
            private_key_pem: PEM-encoded private key
            password: User password for encryption
            
        Returns:
            dict: Encrypted key package with metadata
        """
        # Generate salt and nonce
        salt = self.generate_salt()
        nonce = os.urandom(self.NONCE_SIZE)
        
        # Derive encryption key from password
        encryption_key = self.derive_key_from_password(password, salt)
        
        # Encrypt private key using AES-CTR
        cipher = Cipher(
            algorithms.AES(encryption_key),
            modes.CTR(nonce),
            backend=self.backend
        )
        encryptor = cipher.encryptor()
        
        encrypted_key = encryptor.update(private_key_pem) + encryptor.finalize()
        
        # Create encrypted package
        encrypted_package = {
            'encrypted_key': base64.b64encode(encrypted_key).decode('utf-8'),
            'salt': base64.b64encode(salt).decode('utf-8'),
            'nonce': base64.b64encode(nonce).decode('utf-8'),
            'iterations': self.PBKDF2_ITERATIONS,
            'algorithm': 'AES-256-CTR',
            'kdf': 'PBKDF2-HMAC-SHA256'
        }
        
        return encrypted_package
    
    def decrypt_private_key(self, encrypted_package: dict, password: str) -> bytes:
        """
        Decrypt private key using password
        
        Args:
            encrypted_package: Encrypted key package
            password: User password for decryption
            
        Returns:
            bytes: Decrypted PEM-encoded private key
            
        Raises:
            ValueError: If decryption fails or password is incorrect
        """
        try:
            # Extract components from package
            encrypted_key = base64.b64decode(encrypted_package['encrypted_key'])
            salt = base64.b64decode(encrypted_package['salt'])
            nonce = base64.b64decode(encrypted_package['nonce'])
            
            # Derive decryption key
            decryption_key = self.derive_key_from_password(password, salt)
            
            # Decrypt private key
            cipher = Cipher(
                algorithms.AES(decryption_key),
                modes.CTR(nonce),
                backend=self.backend
            )
            decryptor = cipher.decryptor()
            
            decrypted_key = decryptor.update(encrypted_key) + decryptor.finalize()
            
            return decrypted_key
            
        except Exception as e:
            raise ValueError(f"Failed to decrypt private key: {str(e)}")
    
    def verify_password(self, encrypted_package: dict, password: str) -> bool:
        """
        Verify if password is correct for encrypted private key
        
        Args:
            encrypted_package: Encrypted key package
            password: Password to verify
            
        Returns:
            bool: True if password is correct
        """
        try:
            decrypted_key = self.decrypt_private_key(encrypted_package, password)
            
            # Try to load the decrypted key to verify it's valid
            ecc_manager = ECCManager()
            ecc_manager.deserialize_private_key(decrypted_key)
            
            return True
        except:
            return False
    
    def change_password(self, encrypted_package: dict, old_password: str, new_password: str) -> dict:
        """
        Change password for encrypted private key
        
        Args:
            encrypted_package: Current encrypted key package
            old_password: Current password
            new_password: New password
            
        Returns:
            dict: New encrypted package with new password
            
        Raises:
            ValueError: If old password is incorrect
        """
        # Decrypt with old password
        private_key_pem = self.decrypt_private_key(encrypted_package, old_password)
        
        # Re-encrypt with new password
        return self.encrypt_private_key(private_key_pem, new_password)
    
    def get_key_strength_info(self, password: str) -> dict:
        """
        Analyze password strength for key encryption
        
        Args:
            password: Password to analyze
            
        Returns:
            dict: Password strength information
        """
        strength_info = {
            'length': len(password),
            'has_uppercase': any(c.isupper() for c in password),
            'has_lowercase': any(c.islower() for c in password),
            'has_digits': any(c.isdigit() for c in password),
            'has_special': any(not c.isalnum() for c in password),
            'entropy_bits': 0,
            'strength_level': 'weak'
        }
        
        # Calculate approximate entropy
        charset_size = 0
        if strength_info['has_lowercase']:
            charset_size += 26
        if strength_info['has_uppercase']:
            charset_size += 26
        if strength_info['has_digits']:
            charset_size += 10
        if strength_info['has_special']:
            charset_size += 32  # Common special characters
        
        if charset_size > 0:
            import math
            strength_info['entropy_bits'] = len(password) * math.log2(charset_size)
        
        # Determine strength level
        if strength_info['entropy_bits'] >= 80:
            strength_info['strength_level'] = 'very_strong'
        elif strength_info['entropy_bits'] >= 60:
            strength_info['strength_level'] = 'strong'
        elif strength_info['entropy_bits'] >= 40:
            strength_info['strength_level'] = 'moderate'
        elif strength_info['entropy_bits'] >= 25:
            strength_info['strength_level'] = 'weak'
        else:
            strength_info['strength_level'] = 'very_weak'
        
        return strength_info
    
    def generate_secure_password(self, length: int = 16) -> str:
        """
        Generate cryptographically secure password
        
        Args:
            length: Password length (minimum 12)
            
        Returns:
            str: Generated secure password
        """
        if length < 12:
            raise ValueError("Password length should be at least 12 characters")
        
        # Character sets
        lowercase = 'abcdefghijklmnopqrstuvwxyz'
        uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        digits = '0123456789'
        special = '!@#$%^&*()_+-=[]{}|;:,.<>?'
        
        all_chars = lowercase + uppercase + digits + special
        
        # Ensure at least one character from each set
        password = [
            secrets.choice(lowercase),
            secrets.choice(uppercase),
            secrets.choice(digits),
            secrets.choice(special)
        ]
        
        # Fill remaining length with random characters
        for _ in range(length - 4):
            password.append(secrets.choice(all_chars))
        
        # Shuffle the password
        secrets.SystemRandom().shuffle(password)
        
        return ''.join(password)


class KeyBackupManager:
    """
    Manages backup and recovery of ECC keys
    """
    
    def __init__(self):
        self.storage = SecureKeyStorage()
    
    def create_key_backup(self, private_key_pem: bytes, public_key_pem: bytes, 
                         password: str, metadata: dict = None) -> dict:
        """
        Create encrypted backup of key pair
        
        Args:
            private_key_pem: PEM-encoded private key
            public_key_pem: PEM-encoded public key
            password: Password for encryption
            metadata: Optional metadata about the key
            
        Returns:
            dict: Encrypted backup package
        """
        # Encrypt private key
        encrypted_private = self.storage.encrypt_private_key(private_key_pem, password)
        
        # Create backup package
        backup_package = {
            'private_key': encrypted_private,
            'public_key': base64.b64encode(public_key_pem).decode('utf-8'),
            'metadata': metadata or {},
            'backup_version': '1.0',
            'created_at': str(int(os.times().elapsed))
        }
        
        return backup_package
    
    def restore_from_backup(self, backup_package: dict, password: str) -> Tuple[bytes, bytes]:
        """
        Restore key pair from backup
        
        Args:
            backup_package: Encrypted backup package
            password: Password for decryption
            
        Returns:
            Tuple[bytes, bytes]: (private_key_pem, public_key_pem)
        """
        # Decrypt private key
        private_key_pem = self.storage.decrypt_private_key(
            backup_package['private_key'], 
            password
        )
        
        # Decode public key
        public_key_pem = base64.b64decode(backup_package['public_key'])
        
        return private_key_pem, public_key_pem
    
    def verify_backup_integrity(self, backup_package: dict) -> bool:
        """
        Verify backup package integrity
        
        Args:
            backup_package: Backup package to verify
            
        Returns:
            bool: True if backup is valid
        """
        required_fields = ['private_key', 'public_key', 'backup_version']
        
        for field in required_fields:
            if field not in backup_package:
                return False
        
        return True
