"""
ECC Manager - Core Elliptic Curve Cryptography Operations

This module provides the main ECC functionality for key generation,
encryption, decryption, and signature operations in the Qubix system.
"""

import os
import base64
import hashlib
from typing import Tuple, Dict, Any, Optional

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

from .curves import SupportedCurves, CurveValidator


class ECCManager:
    """
    Main ECC operations manager for the Qubix system
    Handles key generation, ECDH, encryption, and digital signatures
    """
    
    def __init__(self, curve: SupportedCurves = None):
        """
        Initialize ECC Manager with specified curve
        
        Args:
            curve: The elliptic curve to use (defaults to P-256)
        """
        self.curve = curve or SupportedCurves.get_default_curve()
        self.backend = default_backend()
        
        # Validate curve selection
        if not CurveValidator.validate_curve_for_security_level(self.curve):
            raise ValueError(f"Curve {self.curve.value['name']} does not meet minimum security requirements")
    
    def generate_key_pair(self) -> Tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
        """
        Generate a new ECC key pair
        
        Returns:
            Tuple[PrivateKey, PublicKey]: Generated key pair
        """
        try:
            # Generate private key
            private_key = ec.generate_private_key(
                self.curve.get_curve_instance(),
                self.backend
            )
            
            # Get corresponding public key
            public_key = private_key.public_key()
            
            return private_key, public_key
            
        except Exception as e:
            raise RuntimeError(f"Failed to generate ECC key pair: {str(e)}")
    
    def serialize_private_key(self, private_key: ec.EllipticCurvePrivateKey, password: Optional[bytes] = None) -> bytes:
        """
        Serialize private key to PEM format
        
        Args:
            private_key: The private key to serialize
            password: Optional password for encryption
            
        Returns:
            bytes: Serialized private key
        """
        encryption_algorithm = serialization.NoEncryption()
        if password:
            encryption_algorithm = serialization.BestAvailableEncryption(password)
        
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm
        )
    
    def serialize_public_key(self, public_key: ec.EllipticCurvePublicKey) -> bytes:
        """
        Serialize public key to PEM format
        
        Args:
            public_key: The public key to serialize
            
        Returns:
            bytes: Serialized public key
        """
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    def deserialize_private_key(self, private_key_bytes: bytes, password: Optional[bytes] = None) -> ec.EllipticCurvePrivateKey:
        """
        Deserialize private key from PEM format
        
        Args:
            private_key_bytes: Serialized private key
            password: Password if key is encrypted
            
        Returns:
            EllipticCurvePrivateKey: Deserialized private key
        """
        return serialization.load_pem_private_key(
            private_key_bytes,
            password=password,
            backend=self.backend
        )
    
    def deserialize_public_key(self, public_key_bytes: bytes) -> ec.EllipticCurvePublicKey:
        """
        Deserialize public key from PEM format
        
        Args:
            public_key_bytes: Serialized public key
            
        Returns:
            EllipticCurvePublicKey: Deserialized public key
        """
        return serialization.load_pem_public_key(
            public_key_bytes,
            backend=self.backend
        )
    
    def perform_ecdh(self, private_key: ec.EllipticCurvePrivateKey, public_key: ec.EllipticCurvePublicKey) -> bytes:
        """
        Perform Elliptic Curve Diffie-Hellman key exchange
        
        Args:
            private_key: Our private key
            public_key: Other party's public key
            
        Returns:
            bytes: Shared secret
        """
        try:
            shared_key = private_key.exchange(ec.ECDH(), public_key)
            return shared_key
        except Exception as e:
            raise RuntimeError(f"ECDH key exchange failed: {str(e)}")
    
    def derive_symmetric_key(self, shared_secret: bytes, salt: bytes = None, info: bytes = b"qubix-file-encryption") -> bytes:
        """
        Derive symmetric key from shared secret using HKDF
        
        Args:
            shared_secret: The shared secret from ECDH
            salt: Optional salt for key derivation
            info: Context information for key derivation
            
        Returns:
            bytes: Derived 32-byte AES key
        """
        if salt is None:
            salt = os.urandom(16)
        
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # 256-bit key for AES-256
            salt=salt,
            info=info,
            backend=self.backend
        )
        
        return hkdf.derive(shared_secret)
    
    def encrypt_with_aes(self, data: bytes, key: bytes) -> Dict[str, bytes]:
        """
        Encrypt data using AES-256-GCM
        
        Args:
            data: Data to encrypt
            key: 32-byte AES key
            
        Returns:
            Dict containing encrypted data, nonce, and tag
        """
        # Generate random nonce
        nonce = os.urandom(12)  # 96-bit nonce for GCM
        
        # Create cipher
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce),
            backend=self.backend
        )
        encryptor = cipher.encryptor()
        
        # Encrypt data
        ciphertext = encryptor.update(data) + encryptor.finalize()
        
        return {
            'ciphertext': ciphertext,
            'nonce': nonce,
            'tag': encryptor.tag
        }
    
    def decrypt_with_aes(self, encrypted_data: Dict[str, bytes], key: bytes) -> bytes:
        """
        Decrypt data using AES-256-GCM
        
        Args:
            encrypted_data: Dictionary with ciphertext, nonce, and tag
            key: 32-byte AES key
            
        Returns:
            bytes: Decrypted data
        """
        # Create cipher with nonce and tag
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(encrypted_data['nonce'], encrypted_data['tag']),
            backend=self.backend
        )
        decryptor = cipher.decryptor()
        
        # Decrypt data
        return decryptor.update(encrypted_data['ciphertext']) + decryptor.finalize()
    
    def sign_data(self, data: bytes, private_key: ec.EllipticCurvePrivateKey) -> bytes:
        """
        Create digital signature using ECDSA
        
        Args:
            data: Data to sign
            private_key: Private key for signing
            
        Returns:
            bytes: Digital signature
        """
        try:
            signature = private_key.sign(
                data,
                ec.ECDSA(hashes.SHA256())
            )
            return signature
        except Exception as e:
            raise RuntimeError(f"Digital signature failed: {str(e)}")
    
    def verify_signature(self, data: bytes, signature: bytes, public_key: ec.EllipticCurvePublicKey) -> bool:
        """
        Verify digital signature using ECDSA
        
        Args:
            data: Original data
            signature: Digital signature to verify
            public_key: Public key for verification
            
        Returns:
            bool: True if signature is valid
        """
        try:
            public_key.verify(
                signature,
                data,
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except InvalidSignature:
            return False
        except Exception as e:
            raise RuntimeError(f"Signature verification failed: {str(e)}")
    
    def hash_data(self, data: bytes, algorithm: str = 'sha256') -> str:
        """
        Hash data using specified algorithm
        
        Args:
            data: Data to hash
            algorithm: Hash algorithm ('sha256', 'sha384', 'sha512')
            
        Returns:
            str: Hexadecimal hash
        """
        hash_algorithms = {
            'sha256': hashlib.sha256,
            'sha384': hashlib.sha384,
            'sha512': hashlib.sha512
        }
        
        if algorithm not in hash_algorithms:
            raise ValueError(f"Unsupported hash algorithm: {algorithm}")
        
        return hash_algorithms[algorithm](data).hexdigest()
    
    def get_key_info(self, key) -> Dict[str, Any]:
        """
        Get information about an ECC key
        
        Args:
            key: ECC public or private key
            
        Returns:
            Dict: Key information
        """
        key_info = {
            'curve_name': key.curve.name,
            'key_size': key.curve.key_size,
        }
        
        if isinstance(key, ec.EllipticCurvePrivateKey):
            key_info['type'] = 'private'
            key_info['public_key_available'] = True
        else:
            key_info['type'] = 'public'
        
        return key_info
    
    def get_curve_info(self) -> Dict[str, Any]:
        """
        Get information about the current curve
        
        Returns:
            Dict: Curve information
        """
        return self.curve.get_info()


class ECCFileEncryptor:
    """
    Specialized class for file encryption using ECC hybrid approach
    """
    
    def __init__(self, curve: SupportedCurves = None):
        self.ecc_manager = ECCManager(curve)
    
    def encrypt_file_for_recipient(self, file_data: bytes, recipient_public_key: ec.EllipticCurvePublicKey, 
                                 sender_private_key: ec.EllipticCurvePrivateKey) -> Dict[str, Any]:
        """
        Encrypt file for a specific recipient using hybrid encryption
        
        Args:
            file_data: File content to encrypt
            recipient_public_key: Recipient's public key
            sender_private_key: Sender's private key for signature
            
        Returns:
            Dict: Encrypted file package with metadata
        """
        # Generate ephemeral key pair for this encryption
        ephemeral_private, ephemeral_public = self.ecc_manager.generate_key_pair()
        
        # Perform ECDH to get shared secret
        shared_secret = self.ecc_manager.perform_ecdh(ephemeral_private, recipient_public_key)
        
        # Derive AES key from shared secret
        salt = os.urandom(16)
        aes_key = self.ecc_manager.derive_symmetric_key(shared_secret, salt)
        
        # Encrypt file with AES
        encrypted_file = self.ecc_manager.encrypt_with_aes(file_data, aes_key)
        
        # Create file hash for integrity
        file_hash = self.ecc_manager.hash_data(file_data)
        
        # Sign the file hash
        signature = self.ecc_manager.sign_data(file_data, sender_private_key)
        
        return {
            'encrypted_data': encrypted_file,
            'ephemeral_public_key': self.ecc_manager.serialize_public_key(ephemeral_public),
            'salt': salt,
            'file_hash': file_hash,
            'signature': signature,
            'encryption_metadata': {
                'algorithm': 'AES-256-GCM',
                'curve': self.ecc_manager.curve.value['name'],
                'timestamp': str(int(os.times().elapsed))
            }
        }
    
    def decrypt_file_from_sender(self, encrypted_package: Dict[str, Any], 
                               recipient_private_key: ec.EllipticCurvePrivateKey,
                               sender_public_key: ec.EllipticCurvePublicKey) -> bytes:
        """
        Decrypt file and verify sender authenticity
        
        Args:
            encrypted_package: Encrypted file package
            recipient_private_key: Recipient's private key
            sender_public_key: Sender's public key for verification
            
        Returns:
            bytes: Decrypted file data
            
        Raises:
            RuntimeError: If decryption or verification fails
        """
        # Deserialize ephemeral public key
        ephemeral_public = self.ecc_manager.deserialize_public_key(
            encrypted_package['ephemeral_public_key']
        )
        
        # Perform ECDH to recreate shared secret
        shared_secret = self.ecc_manager.perform_ecdh(recipient_private_key, ephemeral_public)
        
        # Derive AES key
        aes_key = self.ecc_manager.derive_symmetric_key(
            shared_secret, 
            encrypted_package['salt']
        )
        
        # Decrypt file
        decrypted_data = self.ecc_manager.decrypt_with_aes(
            encrypted_package['encrypted_data'], 
            aes_key
        )
        
        # Verify file integrity
        calculated_hash = self.ecc_manager.hash_data(decrypted_data)
        if calculated_hash != encrypted_package['file_hash']:
            raise RuntimeError("File integrity check failed")
        
        # Verify signature
        if not self.ecc_manager.verify_signature(
            decrypted_data, 
            encrypted_package['signature'], 
            sender_public_key
        ):
            raise RuntimeError("Digital signature verification failed")
        
        return decrypted_data
