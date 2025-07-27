"""
Batch Operations Module for Qubix

This module provides utilities for handling batch file operations
including bulk encryption, decryption, and file management.
"""

import asyncio
import concurrent.futures
import logging
from typing import List, Dict, Any, Optional, Tuple
from django.conf import settings
from django.contrib.auth.models import User
from django.utils import timezone
from django.db import transaction
import json

from .hybrid_encryption import HybridEncryption
from .file_handler import SecureFileHandler
from .curves import SupportedCurves
from blog.models import SecureFile, SecureFileAccess
from users.models import ECCKeyPair

logger = logging.getLogger(__name__)


class BatchFileProcessor:
    """
    Handle batch file operations with performance optimization
    """
    
    def __init__(self, max_workers: int = 4):
        self.max_workers = max_workers
        self.file_handler = SecureFileHandler()
        self.hybrid_encryption = HybridEncryption()
        
    async def batch_encrypt_files(self, 
                                file_list: List[Dict[str, Any]], 
                                sender_user: User,
                                recipients: List[User],
                                password: str,
                                algorithm: str = 'AES-256-GCM') -> Dict[str, Any]:
        """
        Encrypt multiple files in batch for multiple recipients
        
        Args:
            file_list: List of file dictionaries with 'data', 'filename', 'size'
            sender_user: User uploading the files
            recipients: List of recipient users
            password: Sender's key password for decryption
            algorithm: Encryption algorithm to use
            
        Returns:
            dict: Batch processing results
        """
        results = {
            'success_count': 0,
            'error_count': 0,
            'total_files': len(file_list),
            'total_recipients': len(recipients),
            'files': [],
            'errors': []
        }
        
        try:
            # Get sender's key pair
            sender_keypair = ECCKeyPair.objects.get(user=sender_user, is_active=True)
            sender_private_key = sender_keypair.get_decrypted_private_key(password)
            
            # Get recipient key pairs
            recipient_keypairs = {}
            for recipient in recipients:
                try:
                    keypair = ECCKeyPair.objects.get(user=recipient, is_active=True)
                    recipient_keypairs[recipient.id] = keypair.get_public_key()
                except ECCKeyPair.DoesNotExist:
                    results['errors'].append(f"Recipient {recipient.username} has no active keys")
                    continue
            
            # Process files concurrently
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                # Create tasks for each file
                tasks = []
                for file_data in file_list:
                    task = executor.submit(
                        self._encrypt_single_file,
                        file_data,
                        sender_user,
                        sender_private_key,
                        recipient_keypairs,
                        algorithm
                    )
                    tasks.append(task)
                
                # Process results as they complete
                for i, future in enumerate(concurrent.futures.as_completed(tasks)):
                    try:
                        file_result = future.result()
                        results['files'].append(file_result)
                        results['success_count'] += 1
                        
                        # Log progress
                        progress = ((i + 1) / len(tasks)) * 100
                        logger.info(f"Batch encryption progress: {progress:.1f}%")
                        
                    except Exception as e:
                        results['error_count'] += 1
                        results['errors'].append(f"File {i+1}: {str(e)}")
                        logger.error(f"Batch encryption error for file {i+1}: {str(e)}")
            
            # Calculate processing statistics
            results['processing_time'] = timezone.now()
            results['encryption_efficiency'] = (results['success_count'] / results['total_files']) * 100
            
            return results
            
        except Exception as e:
            results['errors'].append(f"Batch operation failed: {str(e)}")
            logger.error(f"Batch encryption failed: {str(e)}")
            return results
    
    def _encrypt_single_file(self, 
                           file_data: Dict[str, Any],
                           sender_user: User,
                           sender_private_key,
                           recipient_keypairs: Dict[int, Any],
                           algorithm: str) -> Dict[str, Any]:
        """
        Encrypt a single file for all recipients
        
        Args:
            file_data: File information dictionary
            sender_user: User uploading the file
            sender_private_key: Decrypted sender private key
            recipient_keypairs: Dictionary of recipient public keys
            algorithm: Encryption algorithm
            
        Returns:
            dict: File processing result
        """
        file_result = {
            'filename': file_data['filename'],
            'original_size': file_data['size'],
            'recipients': [],
            'secure_file_id': None,
            'errors': []
        }
        
        try:
            # Validate file
            validation = self.file_handler.validate_file(file_data['data'], file_data['filename'])
            if not validation['valid']:
                raise ValueError(f"File validation failed: {', '.join(validation['errors'])}")
            
            # Create SecureFile record with transaction
            with transaction.atomic():
                secure_file = SecureFile.objects.create(
                    original_filename=file_data['filename'],
                    original_size=file_data['size'],
                    encrypted_size=0,  # Will be updated later
                    file_hash=validation['file_info'].get('sha256_hash', ''),
                    encryption_algorithm=algorithm,
                    uploaded_by=sender_user,
                    metadata=json.dumps(validation['file_info'])
                )
                
                file_result['secure_file_id'] = secure_file.id
                
                # Encrypt for each recipient
                total_encrypted_size = 0
                for recipient_id, public_key in recipient_keypairs.items():
                    try:
                        recipient_user = User.objects.get(id=recipient_id)
                        
                        # Encrypt file for this recipient
                        if algorithm == 'ChaCha20-Poly1305':
                            encrypted_package = self.hybrid_encryption.encrypt_file_for_user_chacha20(
                                file_data['data'], public_key, sender_private_key, file_data['filename']
                            )
                        else:  # AES-256-GCM
                            encrypted_package = self.hybrid_encryption.encrypt_file_for_user(
                                file_data['data'], public_key, sender_private_key, file_data['filename']
                            )
                        
                        # Store encrypted file
                        storage_result = self.file_handler.encrypt_and_store_file(
                            file_data['data'],
                            file_data['filename'],
                            public_key,
                            sender_private_key,
                            sender_user.id
                        )
                        
                        # Create access record
                        SecureFileAccess.objects.create(
                            file=secure_file,
                            user=recipient_user,
                            encrypted_symmetric_key=json.dumps(encrypted_package),
                            access_granted_by=sender_user,
                            can_download=True
                        )
                        
                        file_result['recipients'].append({
                            'username': recipient_user.username,
                            'encrypted_size': storage_result['encrypted_size'],
                            'status': 'success'
                        })
                        
                        total_encrypted_size += storage_result['encrypted_size']
                        
                    except Exception as e:
                        file_result['recipients'].append({
                            'username': f'user_{recipient_id}',
                            'status': 'error',
                            'error': str(e)
                        })
                        file_result['errors'].append(f"Encryption failed for user {recipient_id}: {str(e)}")
                
                # Update secure file with total encrypted size
                secure_file.encrypted_size = total_encrypted_size
                secure_file.save(update_fields=['encrypted_size'])
            
            return file_result
            
        except Exception as e:
            file_result['errors'].append(str(e))
            raise e
    
    async def batch_decrypt_files(self,
                                file_access_ids: List[int],
                                user: User,
                                password: str) -> Dict[str, Any]:
        """
        Decrypt multiple files in batch for a user
        
        Args:
            file_access_ids: List of SecureFileAccess IDs
            user: User requesting decryption
            password: User's key password
            
        Returns:
            dict: Batch decryption results
        """
        results = {
            'success_count': 0,
            'error_count': 0,
            'total_files': len(file_access_ids),
            'files': [],
            'errors': []
        }
        
        try:
            # Get user's key pair
            user_keypair = ECCKeyPair.objects.get(user=user, is_active=True)
            user_private_key = user_keypair.get_decrypted_private_key(password)
            
            # Get file access records
            file_accesses = SecureFileAccess.objects.filter(
                id__in=file_access_ids,
                user=user
            ).select_related('file', 'file__uploaded_by')
            
            # Process files concurrently
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                tasks = []
                for file_access in file_accesses:
                    task = executor.submit(
                        self._decrypt_single_file,
                        file_access,
                        user_private_key
                    )
                    tasks.append(task)
                
                # Process results
                for i, future in enumerate(concurrent.futures.as_completed(tasks)):
                    try:
                        file_result = future.result()
                        results['files'].append(file_result)
                        results['success_count'] += 1
                        
                        # Update access record
                        file_access = file_accesses[i]
                        file_access.access_count += 1
                        file_access.last_accessed_at = timezone.now()
                        file_access.save(update_fields=['access_count', 'last_accessed_at'])
                        
                    except Exception as e:
                        results['error_count'] += 1
                        results['errors'].append(f"File {i+1}: {str(e)}")
            
            return results
            
        except Exception as e:
            results['errors'].append(f"Batch decryption failed: {str(e)}")
            return results
    
    def _decrypt_single_file(self,
                           file_access: SecureFileAccess,
                           user_private_key) -> Dict[str, Any]:
        """
        Decrypt a single file
        
        Args:
            file_access: SecureFileAccess instance
            user_private_key: Decrypted user private key
            
        Returns:
            dict: Decryption result
        """
        try:
            # Get sender's public key
            sender_keypair = ECCKeyPair.objects.get(
                user=file_access.file.uploaded_by,
                is_active=True
            )
            sender_public_key = sender_keypair.get_public_key()
            
            # Get encryption metadata
            encryption_metadata = json.loads(file_access.encrypted_symmetric_key)
            
            # Decrypt based on algorithm
            if file_access.file.encryption_algorithm == 'ChaCha20-Poly1305':
                decrypted_data = self.hybrid_encryption.decrypt_file_for_user_chacha20(
                    encryption_metadata, sender_public_key, user_private_key
                )
            else:  # AES-256-GCM
                decrypted_data = self.hybrid_encryption.decrypt_file_for_user(
                    encryption_metadata, sender_public_key, user_private_key
                )
            
            return {
                'file_id': file_access.file.id,
                'filename': file_access.file.original_filename,
                'data': decrypted_data,
                'size': len(decrypted_data),
                'status': 'success'
            }
            
        except Exception as e:
            return {
                'file_id': file_access.file.id,
                'filename': file_access.file.original_filename,
                'status': 'error',
                'error': str(e)
            }
    
    def get_batch_processing_stats(self) -> Dict[str, Any]:
        """
        Get statistics about batch processing capabilities
        
        Returns:
            dict: Processing statistics
        """
        return {
            'max_workers': self.max_workers,
            'supported_operations': [
                'batch_encrypt_files',
                'batch_decrypt_files',
                'concurrent_processing'
            ],
            'supported_algorithms': ['AES-256-GCM', 'ChaCha20-Poly1305'],
            'performance_features': [
                'Concurrent file processing',
                'Transaction-based database operations',
                'Progress tracking',
                'Error isolation',
                'Memory-efficient processing'
            ]
        }


class BatchOperationCache:
    """
    Cache layer for batch operations to improve performance
    """
    
    def __init__(self):
        self.cache = {}
        self.cache_timeout = 300  # 5 minutes
    
    def get_user_keys_cache(self, user_id: int) -> Optional[Dict[str, Any]]:
        """Get cached user keys"""
        cache_key = f"user_keys_{user_id}"
        cached_data = self.cache.get(cache_key)
        
        if cached_data and cached_data['expires'] > timezone.now():
            return cached_data['data']
        return None
    
    def set_user_keys_cache(self, user_id: int, keys_data: Dict[str, Any]):
        """Cache user keys data"""
        cache_key = f"user_keys_{user_id}"
        self.cache[cache_key] = {
            'data': keys_data,
            'expires': timezone.now() + timezone.timedelta(seconds=self.cache_timeout)
        }
    
    def get_file_metadata_cache(self, file_id: str) -> Optional[Dict[str, Any]]:
        """Get cached file metadata"""
        cache_key = f"file_meta_{file_id}"
        cached_data = self.cache.get(cache_key)
        
        if cached_data and cached_data['expires'] > timezone.now():
            return cached_data['data']
        return None
    
    def set_file_metadata_cache(self, file_id: str, metadata: Dict[str, Any]):
        """Cache file metadata"""
        cache_key = f"file_meta_{file_id}"
        self.cache[cache_key] = {
            'data': metadata,
            'expires': timezone.now() + timezone.timedelta(seconds=self.cache_timeout)
        }
    
    def clear_cache(self):
        """Clear all cached data"""
        self.cache.clear()
    
    def cleanup_expired(self):
        """Remove expired cache entries"""
        now = timezone.now()
        expired_keys = [
            key for key, value in self.cache.items()
            if value['expires'] <= now
        ]
        for key in expired_keys:
            del self.cache[key]


# Global cache instance
batch_cache = BatchOperationCache()
