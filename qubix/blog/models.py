from django.db import models
from django.utils import timezone
from django.contrib.auth.models import User
from django.urls import reverse
import os
import json
import uuid


class Post(models.Model):
    VISIBILITY_CHOICES = [
        ('public', 'Public'),
        ('friends', 'Friends Only'),
        ('private', 'Private'),
    ]
    
    title = models.CharField(max_length=100)
    file = models.FileField(null=True, blank=True, upload_to='Files')
    content = models.TextField()
    date_posted = models.DateTimeField(default=timezone.now)
    author = models.ForeignKey(User, on_delete=models.CASCADE)
    visibility = models.CharField(max_length=10, choices=VISIBILITY_CHOICES, default='friends')

    def __str__(self):
        return self.title

    def extension(self):
        name, extension = os.path.splitext(self.file.name)
        return extension

    def get_absolute_url(self):
        return reverse('post-detail', kwargs={'pk': self.pk})

    def can_user_access(self, user):
        """Check if a user can access this post based on visibility settings"""
        if self.visibility == 'public':
            return True
        elif self.visibility == 'private':
            return user == self.author
        elif self.visibility == 'friends':
            if user == self.author:
                return True
            # Import here to avoid circular imports
            from users.models import Friendship
            return Friendship.are_friends(user, self.author)
        return False


class SecureFile(models.Model):
    """
    Model for storing encrypted files using ECC hybrid encryption
    """
    ENCRYPTION_ALGORITHMS = [
        ('ECC-AES-256-GCM', 'ECC + AES-256-GCM'),
        ('ECC-AES-256-GCM-CHUNKED', 'ECC + AES-256-GCM (Chunked)'),
    ]
    
    # File identification
    file_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    original_filename = models.CharField(max_length=255)
    
    # Storage information
    encrypted_file_path = models.CharField(max_length=500)
    original_size = models.BigIntegerField(help_text="Original file size in bytes")
    encrypted_size = models.BigIntegerField(help_text="Encrypted file size in bytes")
    
    # Encryption metadata
    encryption_algorithm = models.CharField(max_length=30, choices=ENCRYPTION_ALGORITHMS)
    curve_name = models.CharField(max_length=20, default='P-256')
    is_chunked = models.BooleanField(default=False)
    
    # File integrity and security
    file_hash = models.CharField(max_length=64, help_text="SHA-256 hash of original file")
    digital_signature = models.TextField(help_text="Base64-encoded digital signature")
    
    # Access control
    uploaded_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='uploaded_secure_files')
    allowed_users = models.ManyToManyField(
        User, 
        through='SecureFileAccess', 
        through_fields=('file', 'user'),
        related_name='accessible_secure_files'
    )
    
    # Metadata and timestamps
    metadata = models.TextField(help_text="JSON-encoded file metadata")
    uploaded_at = models.DateTimeField(auto_now_add=True)
    last_accessed = models.DateTimeField(null=True, blank=True)
    access_count = models.IntegerField(default=0)
    
    # File lifecycle
    is_active = models.BooleanField(default=True)
    expiry_date = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        verbose_name = "Secure File"
        verbose_name_plural = "Secure Files"
        ordering = ['-uploaded_at']
    
    def __str__(self):
        return f"{self.original_filename} ({self.uploaded_by.username})"
    
    def get_metadata(self):
        """
        Get file metadata as dictionary
        
        Returns:
            dict: File metadata
        """
        try:
            return json.loads(self.metadata)
        except json.JSONDecodeError:
            return {}
    
    def set_metadata(self, metadata_dict):
        """
        Set file metadata from dictionary
        
        Args:
            metadata_dict (dict): Metadata to store
        """
        self.metadata = json.dumps(metadata_dict)
    
    def mark_accessed(self, user=None):
        """
        Mark file as accessed and update counters
        
        Args:
            user: User who accessed the file
        """
        self.last_accessed = timezone.now()
        self.access_count += 1
        self.save(update_fields=['last_accessed', 'access_count'])
        
        # Update user-specific access log if user provided
        if user and user.is_authenticated:
            access, created = SecureFileAccess.objects.get_or_create(
                file=self,
                user=user,
                defaults={'access_granted_at': timezone.now()}
            )
            if not created:
                access.last_accessed_at = timezone.now()
                access.access_count += 1
                access.save(update_fields=['last_accessed_at', 'access_count'])
    
    def can_user_access(self, user):
        """
        Check if user has access to this secure file
        
        Args:
            user: Django User instance
            
        Returns:
            bool: True if user can access file
        """
        if not user.is_authenticated:
            return False
        
        # Owner always has access
        if user == self.uploaded_by:
            return True
        
        # Check if user is in allowed users
        return self.allowed_users.filter(id=user.id).exists()
    
    def is_expired(self):
        """
        Check if file has expired
        
        Returns:
            bool: True if file is expired
        """
        if self.expiry_date:
            return timezone.now() > self.expiry_date
        return False
    
    def get_file_size_display(self):
        """
        Get human-readable file size
        
        Returns:
            str: Formatted file size
        """
        size = self.original_size
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"
    
    def get_encryption_info(self):
        """
        Get encryption information for display
        
        Returns:
            dict: Encryption details
        """
        return {
            'algorithm': self.get_encryption_algorithm_display(),
            'curve': self.curve_name,
            'chunked': self.is_chunked,
            'file_hash': self.file_hash[:16] + '...',  # Truncated for display
            'has_signature': bool(self.digital_signature)
        }


class SecureFileAccess(models.Model):
    """
    Through model for tracking user access to secure files
    """
    file = models.ForeignKey(SecureFile, on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    
    # Access permissions
    can_download = models.BooleanField(default=True)
    can_share = models.BooleanField(default=False)
    
    # Access tracking
    access_granted_at = models.DateTimeField(auto_now_add=True)
    access_granted_by = models.ForeignKey(
        User, 
        on_delete=models.CASCADE, 
        related_name='granted_file_access',
        null=True, 
        blank=True
    )
    
    # Usage statistics
    last_accessed_at = models.DateTimeField(null=True, blank=True)
    access_count = models.IntegerField(default=0)
    
    # Expiration
    access_expires_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        unique_together = ['file', 'user']
        verbose_name = "Secure File Access"
        verbose_name_plural = "Secure File Access Records"
    
    def __str__(self):
        return f"{self.user.username} -> {self.file.original_filename}"
    
    def is_access_expired(self):
        """
        Check if access permission has expired
        
        Returns:
            bool: True if access is expired
        """
        if self.access_expires_at:
            return timezone.now() > self.access_expires_at
        return False
    
    def can_access(self):
        """
        Check if this access record allows current access
        
        Returns:
            bool: True if access is allowed
        """
        if self.is_access_expired():
            return False
        if not self.file.is_active:
            return False
        if self.file.is_expired():
            return False
        return True
