"""
File Handler Module for Qubix

This module provides utilities for handling file operations
including secure file upload, download, and management.
"""

import os
import mimetypes
import uuid
import hashlib
from typing import Dict, Any, Optional, List
from django.conf import settings
from django.core.files.storage import default_storage
from django.core.files.base import ContentFile
from django.utils import timezone

from .hybrid_encryption import HybridEncryption
from .curves import SupportedCurves


class SecureFileHandler:
    """
    Handles secure file operations with encryption/decryption
    """
    
    def __init__(self, curve: SupportedCurves = SupportedCurves.P256):
        self.encryption = HybridEncryption(curve)
        self.upload_path = getattr(settings, 'SECURE_FILES_ROOT', 'secure_files')
        
        # File size limits (in bytes)
        self.MAX_FILE_SIZE = getattr(settings, 'MAX_SECURE_FILE_SIZE', 100 * 1024 * 1024)  # 100MB
        self.CHUNK_SIZE = getattr(settings, 'SECURE_FILE_CHUNK_SIZE', 1024 * 1024)  # 1MB chunks
        
        # Allowed file types (can be configured in settings)
        self.ALLOWED_EXTENSIONS = getattr(settings, 'ALLOWED_SECURE_EXTENSIONS', {
            'documents': ['.pdf', '.doc', '.docx', '.txt', '.rtf', '.odt'],
            'images': ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.webp'],
            'videos': ['.mp4', '.avi', '.mkv', '.mov', '.wmv', '.webm'],
            'audio': ['.mp3', '.wav', '.flac', '.aac', '.ogg'],
            'archives': ['.zip', '.rar', '.7z', '.tar', '.gz'],
            'code': ['.py', '.js', '.html', '.css', '.json', '.xml', '.sql']
        })
    
    def validate_file(self, file_data: bytes, filename: str) -> Dict[str, Any]:
        """
        Validate file before processing
        
        Args:
            file_data: File content
            filename: Original filename
            
        Returns:
            dict: Validation result
        """
        validation_result = {
            'valid': True,
            'errors': [],
            'warnings': [],
            'file_info': {}
        }
        
        # Check file size
        file_size = len(file_data)
        if file_size == 0:
            validation_result['valid'] = False
            validation_result['errors'].append("File is empty")
        elif file_size > self.MAX_FILE_SIZE:
            validation_result['valid'] = False
            validation_result['errors'].append(f"File size ({file_size} bytes) exceeds maximum allowed size ({self.MAX_FILE_SIZE} bytes)")
        
        # Check file extension
        file_extension = os.path.splitext(filename)[1].lower()
        allowed_extensions = []
        for category, extensions in self.ALLOWED_EXTENSIONS.items():
            allowed_extensions.extend(extensions)
        
        if file_extension not in allowed_extensions:
            validation_result['warnings'].append(f"File extension '{file_extension}' may not be supported")
        
        # Detect MIME type
        mime_type, _ = mimetypes.guess_type(filename)
        
        # Calculate file hash for integrity checking
        file_hash = hashlib.sha256(file_data).hexdigest()
        
        # Basic file info
        validation_result['file_info'] = {
            'filename': filename,
            'size': file_size,
            'extension': file_extension,
            'mime_type': mime_type,
            'size_mb': round(file_size / (1024 * 1024), 2),
            'category': self._get_file_category(file_extension),
            'file_hash': file_hash
        }
        
        return validation_result
    
    def encrypt_and_store_file(self, file_data: bytes, filename: str,
                              recipient_public_key, sender_private_key,
                              user_id: int) -> Dict[str, Any]:
        """
        Encrypt file and store it securely
        
        Args:
            file_data: Raw file data
            filename: Original filename
            recipient_public_key: ECC public key of recipient
            sender_private_key: ECC private key of sender
            user_id: ID of the user uploading the file
            
        Returns:
            dict: Storage information
        """
        try:
            # Validate file first
            validation = self.validate_file(file_data, filename)
            if not validation['valid']:
                raise ValueError(f"File validation failed: {', '.join(validation['errors'])}")
            
            # Generate unique file ID
            file_id = str(uuid.uuid4())
            
            # Determine if we need chunked encryption
            file_size = len(file_data)
            use_chunking = file_size > self.CHUNK_SIZE
            
            if use_chunking:
                # Use chunked encryption for large files
                # First save to temporary location
                temp_path = os.path.join(settings.MEDIA_ROOT, 'temp', f"{file_id}.tmp")
                os.makedirs(os.path.dirname(temp_path), exist_ok=True)
                
                with open(temp_path, 'wb') as temp_file:
                    temp_file.write(file_data)
                
                # Encrypt in chunks
                encrypted_package = self.encryption.encrypt_file_chunks(
                    temp_path, recipient_public_key, sender_private_key, self.CHUNK_SIZE
                )
                
                # Clean up temp file
                os.remove(temp_path)
                
            else:
                # Use standard encryption for smaller files
                encrypted_package = self.encryption.encrypt_file_for_user(
                    file_data, recipient_public_key, sender_private_key, filename
                )
            
            # Store encrypted package
            storage_path = os.path.join(self.upload_path, f"{file_id}.enc")
            encrypted_content = self._serialize_encrypted_package(encrypted_package)
            
            # Save to storage
            saved_path = default_storage.save(storage_path, ContentFile(encrypted_content))
            
            return {
                'file_id': file_id,
                'storage_path': saved_path,
                'original_filename': filename,
                'encrypted_size': len(encrypted_content),
                'original_size': file_size,
                'chunked': use_chunking,
                'metadata': encrypted_package.get('metadata', {}),
                'uploaded_at': timezone.now().isoformat(),
                'validation_info': validation
            }
            
        except Exception as e:
            raise RuntimeError(f"File encryption and storage failed: {str(e)}")
    
    def retrieve_and_decrypt_file(self, storage_path: str, file_id: str,
                                 recipient_private_key, sender_public_key) -> Dict[str, Any]:
        """
        Retrieve and decrypt stored file
        
        Args:
            storage_path: Path to encrypted file
            file_id: Unique file identifier
            recipient_private_key: ECC private key for decryption
            sender_public_key: ECC public key for verification
            
        Returns:
            dict: Decrypted file information
        """
        try:
            # Read encrypted package
            if not default_storage.exists(storage_path):
                raise FileNotFoundError(f"Encrypted file not found: {storage_path}")
            
            with default_storage.open(storage_path, 'rb') as encrypted_file:
                encrypted_content = encrypted_file.read()
            
            # Deserialize encrypted package
            encrypted_package = self._deserialize_encrypted_package(encrypted_content)
            
            # Check if file was chunked
            is_chunked = 'chunks' in encrypted_package
            
            if is_chunked:
                # Create temporary output file for chunked decryption
                temp_output = os.path.join(settings.MEDIA_ROOT, 'temp', f"{file_id}_decrypted.tmp")
                os.makedirs(os.path.dirname(temp_output), exist_ok=True)
                
                # Decrypt chunks
                metadata = self.encryption.decrypt_file_chunks(
                    encrypted_package, recipient_private_key, sender_public_key, temp_output
                )
                
                # Read decrypted file
                with open(temp_output, 'rb') as f:
                    file_data = f.read()
                
                # Clean up temp file
                os.remove(temp_output)
                
            else:
                # Standard decryption
                file_data, metadata = self.encryption.decrypt_file_from_user(
                    encrypted_package, recipient_private_key, sender_public_key
                )
            
            return {
                'file_data': file_data,
                'metadata': metadata,
                'size': len(file_data),
                'chunked': is_chunked,
                'decrypted_at': timezone.now().isoformat()
            }
            
        except Exception as e:
            raise RuntimeError(f"File retrieval and decryption failed: {str(e)}")
    
    def delete_secure_file(self, storage_path: str) -> bool:
        """
        Securely delete encrypted file
        
        Args:
            storage_path: Path to encrypted file
            
        Returns:
            bool: True if deletion successful
        """
        try:
            if default_storage.exists(storage_path):
                default_storage.delete(storage_path)
                return True
            return False
        except Exception:
            return False
    
    def get_file_info(self, storage_path: str) -> Optional[Dict[str, Any]]:
        """
        Get information about stored encrypted file
        
        Args:
            storage_path: Path to encrypted file
            
        Returns:
            dict: File information or None if not found
        """
        try:
            if not default_storage.exists(storage_path):
                return None
            
            # Get file stats
            file_size = default_storage.size(storage_path)
            modified_time = default_storage.get_modified_time(storage_path)
            
            # Try to read metadata from encrypted package
            with default_storage.open(storage_path, 'rb') as encrypted_file:
                encrypted_content = encrypted_file.read()
            
            encrypted_package = self._deserialize_encrypted_package(encrypted_content)
            metadata = encrypted_package.get('metadata', {})
            
            return {
                'storage_path': storage_path,
                'encrypted_size': file_size,
                'modified_time': modified_time,
                'metadata': metadata,
                'chunked': 'chunks' in encrypted_package
            }
            
        except Exception:
            return {
                'storage_path': storage_path,
                'error': 'Unable to read file information'
            }
    
    def _get_file_category(self, extension: str) -> str:
        """
        Determine file category based on extension
        
        Args:
            extension: File extension
            
        Returns:
            str: File category
        """
        for category, extensions in self.ALLOWED_EXTENSIONS.items():
            if extension in extensions:
                return category
        return 'other'
    
    def _serialize_encrypted_package(self, package: Dict[str, Any]) -> bytes:
        """
        Serialize encrypted package for storage
        
        Args:
            package: Encrypted package dictionary
            
        Returns:
            bytes: Serialized package
        """
        import json
        return json.dumps(package, indent=None, separators=(',', ':')).encode('utf-8')
    
    def _deserialize_encrypted_package(self, data: bytes) -> Dict[str, Any]:
        """
        Deserialize encrypted package from storage
        
        Args:
            data: Serialized package bytes
            
        Returns:
            dict: Encrypted package dictionary
        """
        import json
        return json.loads(data.decode('utf-8'))
    
    def get_storage_stats(self) -> Dict[str, Any]:
        """
        Get statistics about secure file storage
        
        Returns:
            dict: Storage statistics
        """
        try:
            # This would be implemented based on your storage backend
            # For now, return basic info
            return {
                'handler_version': '1.0',
                'max_file_size_mb': self.MAX_FILE_SIZE / (1024 * 1024),
                'chunk_size_mb': self.CHUNK_SIZE / (1024 * 1024),
                'allowed_categories': list(self.ALLOWED_EXTENSIONS.keys()),
                'encryption_algorithm': 'ECC + AES-256-GCM',
                'features': [
                    'File validation',
                    'Chunked encryption for large files',
                    'MIME type detection',
                    'Secure deletion',
                    'Metadata preservation'
                ]
            }
        except Exception as e:
            return {'error': str(e)}
