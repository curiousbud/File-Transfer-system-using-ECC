"""
Hybrid Encryption Module for Qubix

This module implements hybrid encryption combining ECC (ECDH) and AES
for secure file transfer. Uses ECC for key exchange and AES for actual
file encryption to get the best of both worlds.
"""

import os
import json
import base64
from typing import Dict, Any, Tuple, Optional
from datetime import datetime

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.backends import default_backend

from .ecc_manager import ECCManager
from .curves import SupportedCurves


class HybridEncryption:
    """
    Hybrid encryption using ECC + AES for secure file transfer
    
    This class provides high-level encryption/decryption operations
    that combine the security of ECC with the performance of AES.
    """
    
    def __init__(self, curve: SupportedCurves = SupportedCurves.P256):
        self.ecc_manager = ECCManager(curve)
        self.backend = default_backend()
        
        # Security parameters
        self.AES_KEY_SIZE = 32  # 256-bit AES key
        self.IV_SIZE = 16       # 128-bit IV for AES-GCM
        self.TAG_SIZE = 16      # 128-bit authentication tag
        
    def encrypt_file_for_user(self, file_data: bytes, recipient_public_key: ec.EllipticCurvePublicKey,
                             sender_private_key: ec.EllipticCurvePrivateKey, 
                             filename: str = "unknown") -> Dict[str, Any]:
        """
        Encrypt file data for a specific recipient using hybrid encryption
        
        Args:
            file_data: Raw file bytes to encrypt
            recipient_public_key: Recipient's ECC public key
            sender_private_key: Sender's ECC private key for signing
            filename: Original filename for metadata
            
        Returns:
            dict: Complete encrypted package with metadata
        """
        try:
            # Generate ephemeral key pair for this session
            ephemeral_private, ephemeral_public = self.ecc_manager.generate_key_pair()
            
            # Perform ECDH with recipient's public key
            shared_secret = self.ecc_manager.perform_ecdh(ephemeral_private, recipient_public_key)
            
            # Generate salt for key derivation
            salt = os.urandom(32)
            
            # Derive AES key from shared secret
            aes_key = self._derive_aes_key(shared_secret, salt)
            
            # Encrypt file data with AES-GCM
            encrypted_data, auth_tag = self._encrypt_with_aes_gcm(file_data, aes_key)
            
            # Create file hash for integrity verification
            file_hash = self.ecc_manager.hash_data(file_data)
            
            # Sign the file hash with sender's private key
            signature = self.ecc_manager.sign_data(file_data, sender_private_key)
            
            # Create encrypted package
            encrypted_package = {
                'encrypted_data': base64.b64encode(encrypted_data).decode('utf-8'),
                'ephemeral_public_key': base64.b64encode(
                    self.ecc_manager.serialize_public_key(ephemeral_public)
                ).decode('utf-8'),
                'salt': base64.b64encode(salt).decode('utf-8'),
                'auth_tag': base64.b64encode(auth_tag).decode('utf-8'),
                'file_hash': file_hash,
                'signature': base64.b64encode(signature).decode('utf-8'),
                'metadata': {
                    'filename': filename,
                    'file_size': len(file_data),
                    'algorithm': 'ECC-AES-256-GCM',
                    'curve': self.ecc_manager.curve.value['name'],
                    'timestamp': datetime.now().isoformat(),
                    'version': '1.0'
                }
            }
            
            return encrypted_package
            
        except Exception as e:
            raise RuntimeError(f"File encryption failed: {str(e)}")
    
    def decrypt_file_from_user(self, encrypted_package: Dict[str, Any],
                              recipient_private_key: ec.EllipticCurvePrivateKey,
                              sender_public_key: ec.EllipticCurvePublicKey) -> Tuple[bytes, Dict[str, Any]]:
        """
        Decrypt file data from encrypted package
        
        Args:
            encrypted_package: Encrypted file package
            recipient_private_key: Recipient's ECC private key
            sender_public_key: Sender's public key for signature verification
            
        Returns:
            tuple: (decrypted_file_data, metadata)
        """
        try:
            # Extract components from package
            encrypted_data = base64.b64decode(encrypted_package['encrypted_data'])
            ephemeral_public_key_bytes = base64.b64decode(encrypted_package['ephemeral_public_key'])
            salt = base64.b64decode(encrypted_package['salt'])
            auth_tag = base64.b64decode(encrypted_package['auth_tag'])
            signature = base64.b64decode(encrypted_package['signature'])
            
            # Deserialize ephemeral public key
            ephemeral_public_key = self.ecc_manager.deserialize_public_key(ephemeral_public_key_bytes)
            
            # Perform ECDH to recreate shared secret
            shared_secret = self.ecc_manager.perform_ecdh(recipient_private_key, ephemeral_public_key)
            
            # Derive AES key from shared secret
            aes_key = self._derive_aes_key(shared_secret, salt)
            
            # Decrypt file data
            decrypted_data = self._decrypt_with_aes_gcm(encrypted_data, aes_key, auth_tag)
            
            # Verify file integrity
            calculated_hash = self.ecc_manager.hash_data(decrypted_data)
            if calculated_hash != encrypted_package['file_hash']:
                raise RuntimeError("File integrity check failed")
            
            # Verify sender's signature
            if not self.ecc_manager.verify_signature(decrypted_data, signature, sender_public_key):
                raise RuntimeError("Digital signature verification failed")
            
            return decrypted_data, encrypted_package.get('metadata', {})
            
        except Exception as e:
            raise RuntimeError(f"File decryption failed: {str(e)}")
    
    def encrypt_file_chunks(self, file_path: str, recipient_public_key: ec.EllipticCurvePublicKey,
                           sender_private_key: ec.EllipticCurvePrivateKey,
                           chunk_size: int = 1024 * 1024) -> Dict[str, Any]:
        """
        Encrypt large files by processing them in chunks
        
        Args:
            file_path: Path to file to encrypt
            recipient_public_key: Recipient's public key
            sender_private_key: Sender's private key
            chunk_size: Size of each chunk in bytes (default 1MB)
            
        Returns:
            dict: Encrypted package with chunked data
        """
        try:
            import hashlib
            
            # Generate session keys
            ephemeral_private, ephemeral_public = self.ecc_manager.generate_key_pair()
            shared_secret = self.ecc_manager.perform_ecdh(ephemeral_private, recipient_public_key)
            salt = os.urandom(32)
            aes_key = self._derive_aes_key(shared_secret, salt)
            
            encrypted_chunks = []
            file_hash = hashlib.sha256()
            total_size = 0
            
            with open(file_path, 'rb') as f:
                chunk_index = 0
                while True:
                    chunk_data = f.read(chunk_size)
                    if not chunk_data:
                        break
                    
                    # Update file hash
                    file_hash.update(chunk_data)
                    total_size += len(chunk_data)
                    
                    # Encrypt chunk
                    encrypted_chunk, auth_tag = self._encrypt_with_aes_gcm(
                        chunk_data, aes_key, additional_data=str(chunk_index).encode()
                    )
                    
                    encrypted_chunks.append({
                        'index': chunk_index,
                        'data': base64.b64encode(encrypted_chunk).decode('utf-8'),
                        'auth_tag': base64.b64encode(auth_tag).decode('utf-8'),
                        'size': len(chunk_data)
                    })
                    
                    chunk_index += 1
            
            # Create file signature
            with open(file_path, 'rb') as f:
                file_data = f.read()
                signature = self.ecc_manager.sign_data(file_data, sender_private_key)
            
            return {
                'chunks': encrypted_chunks,
                'ephemeral_public_key': base64.b64encode(
                    self.ecc_manager.serialize_public_key(ephemeral_public)
                ).decode('utf-8'),
                'salt': base64.b64encode(salt).decode('utf-8'),
                'file_hash': file_hash.hexdigest(),
                'signature': base64.b64encode(signature).decode('utf-8'),
                'metadata': {
                    'filename': os.path.basename(file_path),
                    'total_size': total_size,
                    'chunk_count': len(encrypted_chunks),
                    'chunk_size': chunk_size,
                    'algorithm': 'ECC-AES-256-GCM-CHUNKED',
                    'curve': self.ecc_manager.curve.value['name'],
                    'timestamp': datetime.now().isoformat(),
                    'version': '1.0'
                }
            }
            
        except Exception as e:
            raise RuntimeError(f"Chunked file encryption failed: {str(e)}")
    
    def decrypt_file_chunks(self, encrypted_package: Dict[str, Any],
                           recipient_private_key: ec.EllipticCurvePrivateKey,
                           sender_public_key: ec.EllipticCurvePublicKey,
                           output_path: str) -> Dict[str, Any]:
        """
        Decrypt chunked file data
        
        Args:
            encrypted_package: Chunked encrypted package
            recipient_private_key: Recipient's private key
            sender_public_key: Sender's public key
            output_path: Path to save decrypted file
            
        Returns:
            dict: Decryption metadata
        """
        try:
            import hashlib
            
            # Extract encryption parameters
            ephemeral_public_key_bytes = base64.b64decode(encrypted_package['ephemeral_public_key'])
            salt = base64.b64decode(encrypted_package['salt'])
            signature = base64.b64decode(encrypted_package['signature'])
            
            # Recreate shared secret
            ephemeral_public_key = self.ecc_manager.deserialize_public_key(ephemeral_public_key_bytes)
            shared_secret = self.ecc_manager.perform_ecdh(recipient_private_key, ephemeral_public_key)
            aes_key = self._derive_aes_key(shared_secret, salt)
            
            # Decrypt chunks in order
            file_hash = hashlib.sha256()
            
            with open(output_path, 'wb') as output_file:
                chunks = sorted(encrypted_package['chunks'], key=lambda x: x['index'])
                
                for chunk in chunks:
                    encrypted_data = base64.b64decode(chunk['data'])
                    auth_tag = base64.b64decode(chunk['auth_tag'])
                    
                    # Decrypt chunk
                    decrypted_chunk = self._decrypt_with_aes_gcm(
                        encrypted_data, aes_key, auth_tag,
                        additional_data=str(chunk['index']).encode()
                    )
                    
                    # Update hash and write to file
                    file_hash.update(decrypted_chunk)
                    output_file.write(decrypted_chunk)
            
            # Verify file integrity
            if file_hash.hexdigest() != encrypted_package['file_hash']:
                raise RuntimeError("File integrity check failed")
            
            # Verify signature
            with open(output_path, 'rb') as f:
                file_data = f.read()
                if not self.ecc_manager.verify_signature(file_data, signature, sender_public_key):
                    raise RuntimeError("Digital signature verification failed")
            
            return encrypted_package.get('metadata', {})
            
        except Exception as e:
            raise RuntimeError(f"Chunked file decryption failed: {str(e)}")
    
    def _derive_aes_key(self, shared_secret: bytes, salt: bytes, info: bytes = b"qubix-file-encryption") -> bytes:
        """
        Derive AES key from shared secret using HKDF
        
        Args:
            shared_secret: Shared secret from ECDH
            salt: Random salt
            info: Context information
            
        Returns:
            bytes: Derived AES key
        """
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=self.AES_KEY_SIZE,
            salt=salt,
            info=info,
            backend=self.backend
        )
        return hkdf.derive(shared_secret)
    
    def _encrypt_with_aes_gcm(self, data: bytes, key: bytes, 
                             additional_data: bytes = None) -> Tuple[bytes, bytes]:
        """
        Encrypt data using AES-GCM
        
        Args:
            data: Data to encrypt
            key: AES key
            additional_data: Additional authenticated data
            
        Returns:
            tuple: (encrypted_data, auth_tag)
        """
        # Generate random IV
        iv = os.urandom(self.IV_SIZE)
        
        # Create cipher
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        
        # Add additional authenticated data if provided
        if additional_data:
            encryptor.authenticate_additional_data(additional_data)
        
        # Encrypt data
        encrypted_data = encryptor.update(data) + encryptor.finalize()
        
        # Return encrypted data with IV prepended and authentication tag
        return iv + encrypted_data, encryptor.tag
    
    def _decrypt_with_aes_gcm(self, encrypted_data: bytes, key: bytes, auth_tag: bytes,
                             additional_data: bytes = None) -> bytes:
        """
        Decrypt data using AES-GCM
        
        Args:
            encrypted_data: Data to decrypt (IV + ciphertext)
            key: AES key
            auth_tag: Authentication tag
            additional_data: Additional authenticated data
            
        Returns:
            bytes: Decrypted data
        """
        # Extract IV and ciphertext
        iv = encrypted_data[:self.IV_SIZE]
        ciphertext = encrypted_data[self.IV_SIZE:]
        
        # Create cipher
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, auth_tag), backend=self.backend)
        decryptor = cipher.decryptor()
        
        # Add additional authenticated data if provided
        if additional_data:
            decryptor.authenticate_additional_data(additional_data)
        
        # Decrypt and verify
        return decryptor.update(ciphertext) + decryptor.finalize()
    
    def encrypt_file_for_user_chacha20(self, file_data: bytes, recipient_public_key: ec.EllipticCurvePublicKey,
                                      sender_private_key: ec.EllipticCurvePrivateKey, 
                                      filename: str = "unknown") -> Dict[str, Any]:
        """
        Encrypt file data using ChaCha20-Poly1305 for mobile/cross-platform compatibility
        
        Args:
            file_data: Raw file bytes to encrypt
            recipient_public_key: Recipient's ECC public key
            sender_private_key: Sender's ECC private key
            filename: Name of the file being encrypted
            
        Returns:
            dict: Encryption package with metadata
        """
        # Perform ECDH key exchange
        shared_secret = self.ecc_manager.perform_ecdh(sender_private_key, recipient_public_key)
        
        # Derive ChaCha20 key from shared secret
        chacha_key = self._derive_chacha20_key(shared_secret)
        
        # Encrypt with ChaCha20-Poly1305
        encrypted_data = self._encrypt_with_chacha20(file_data, chacha_key)
        
        # Calculate file hash for integrity
        file_hash = hashes.Hash(hashes.SHA256(), backend=self.backend)
        file_hash.update(file_data)
        
        return {
            'encrypted_data': base64.b64encode(encrypted_data).decode('utf-8'),
            'algorithm': 'ChaCha20-Poly1305',
            'filename': filename,
            'file_size': len(file_data),
            'file_hash': file_hash.finalize().hex(),
            'encryption_timestamp': datetime.utcnow().isoformat(),
            'sender_curve': self.ecc_manager.curve.value['name']
        }
    
    def decrypt_file_for_user_chacha20(self, encryption_package: Dict[str, Any],
                                      sender_public_key: ec.EllipticCurvePublicKey,
                                      recipient_private_key: ec.EllipticCurvePrivateKey) -> bytes:
        """
        Decrypt file data using ChaCha20-Poly1305
        
        Args:
            encryption_package: Encrypted file package
            sender_public_key: Sender's ECC public key
            recipient_private_key: Recipient's ECC private key
            
        Returns:
            bytes: Decrypted file data
        """
        # Perform ECDH key exchange
        shared_secret = self.ecc_manager.perform_ecdh(recipient_private_key, sender_public_key)
        
        # Derive ChaCha20 key from shared secret
        chacha_key = self._derive_chacha20_key(shared_secret)
        
        # Decrypt data
        encrypted_data = base64.b64decode(encryption_package['encrypted_data'])
        decrypted_data = self._decrypt_with_chacha20(encrypted_data, chacha_key)
        
        # Verify file integrity
        file_hash = hashes.Hash(hashes.SHA256(), backend=self.backend)
        file_hash.update(decrypted_data)
        calculated_hash = file_hash.finalize().hex()
        
        if calculated_hash != encryption_package['file_hash']:
            raise ValueError("File integrity verification failed")
        
        return decrypted_data
    
    def _derive_chacha20_key(self, shared_secret: bytes) -> bytes:
        """
        Derive ChaCha20 key from shared secret using HKDF
        
        Args:
            shared_secret: ECDH shared secret
            
        Returns:
            bytes: 32-byte ChaCha20 key
        """
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # ChaCha20 uses 256-bit keys
            salt=None,
            info=b'ChaCha20-Poly1305 encryption',
            backend=self.backend
        )
        return hkdf.derive(shared_secret)
    
    def _encrypt_with_chacha20(self, data: bytes, key: bytes) -> bytes:
        """
        Encrypt data using ChaCha20-Poly1305
        
        Args:
            data: Data to encrypt
            key: ChaCha20 key (32 bytes)
            
        Returns:
            bytes: Nonce + encrypted data (with authentication tag)
        """
        # Generate random nonce
        nonce = os.urandom(12)  # ChaCha20-Poly1305 uses 96-bit nonces
        
        # Create ChaCha20-Poly1305 instance
        chacha = ChaCha20Poly1305(key)
        
        # Encrypt data (automatically includes authentication tag)
        ciphertext = chacha.encrypt(nonce, data, None)
        
        # Return nonce + ciphertext
        return nonce + ciphertext
    
    def _decrypt_with_chacha20(self, encrypted_data: bytes, key: bytes) -> bytes:
        """
        Decrypt data using ChaCha20-Poly1305
        
        Args:
            encrypted_data: Nonce + ciphertext (with auth tag)
            key: ChaCha20 key (32 bytes)
            
        Returns:
            bytes: Decrypted data
        """
        # Extract nonce and ciphertext
        nonce = encrypted_data[:12]  # First 12 bytes are nonce
        ciphertext = encrypted_data[12:]  # Rest is ciphertext + tag
        
        # Create ChaCha20-Poly1305 instance
        chacha = ChaCha20Poly1305(key)
        
        # Decrypt and verify
        return chacha.decrypt(nonce, ciphertext, None)
    
    def get_encryption_info(self) -> Dict[str, Any]:
        """
        Get information about the encryption configuration
        
        Returns:
            dict: Encryption configuration details
        """
        return {
            'supported_algorithms': [
                'ECC + AES-256-GCM Hybrid Encryption',
                'ECC + ChaCha20-Poly1305 Hybrid Encryption'
            ],
            'curve': self.ecc_manager.curve.value['name'],
            'aes_config': {
                'key_size': self.AES_KEY_SIZE * 8,  # Convert to bits
                'iv_size': self.IV_SIZE * 8,
                'tag_size': self.TAG_SIZE * 8,
                'performance': 'Excellent on AES-NI hardware',
                'recommended_for': 'High-throughput server applications'
            },
            'chacha20_config': {
                'key_size': 256,  # bits
                'nonce_size': 96,  # bits
                'tag_size': 128,  # bits
                'performance': 'Excellent on all platforms',
                'recommended_for': 'Mobile devices and general purpose'
            },
            'kdf': 'HKDF-SHA256',
            'features': [
                'Perfect Forward Secrecy',
                'Authenticated Encryption',
                'Digital Signatures',
                'File Integrity Verification',
                'Large File Support (Chunking)',
                'Cross-platform Compatibility (ChaCha20)',
                'Hardware Acceleration Support (AES-GCM)'
            ]
        }
