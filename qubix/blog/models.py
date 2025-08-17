from django.db import models
from django.utils import timezone
from django.contrib.auth.models import User
from django.urls import reverse
from django.conf import settings
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

    @classmethod
    def get_allowed_visibility_choices(cls):
        """Return visibility choices based on feature flags"""
        choices = [
            ('friends', 'Friends Only'),
            ('private', 'Private'),
        ]
        
        # Only add public option if enabled in settings
        if getattr(settings, 'ENABLE_PUBLIC_SHARING', False):
            choices.insert(0, ('public', 'Public'))
        
        return choices

class SecureFile(models.Model):
    ENCRYPTION_ALGORITHMS = [
        ('ECC-AES-256-GCM', 'ECC + AES-256-GCM'),
        ('ECC-AES-256-GCM-CHUNKED', 'ECC + AES-256-GCM (Chunked)'),
    ]
    file_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    original_filename = models.CharField(max_length=255)
    encrypted_file_path = models.CharField(max_length=500)
    original_size = models.BigIntegerField()
    encrypted_size = models.BigIntegerField()
    encryption_algorithm = models.CharField(max_length=30, choices=ENCRYPTION_ALGORITHMS)
    curve_name = models.CharField(max_length=20, default='P-256')
    is_chunked = models.BooleanField(default=False)
    file_hash = models.CharField(max_length=64)
    digital_signature = models.TextField()
    uploaded_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='uploaded_secure_files_blog')
    allowed_users = models.ManyToManyField(User, through='SecureFileAccess', through_fields=('file', 'user'), related_name='accessible_secure_files_blog')
    metadata = models.TextField()
    uploaded_at = models.DateTimeField(auto_now_add=True)
    last_accessed = models.DateTimeField(null=True, blank=True)
    access_count = models.IntegerField(default=0)
    is_active = models.BooleanField(default=True)
    expiry_date = models.DateTimeField(null=True, blank=True)
    class Meta:
        verbose_name = "Secure File (Blog)"
        verbose_name_plural = "Secure Files (Blog)"
        ordering = ['-uploaded_at']
    def __str__(self):
        return f"{self.original_filename} ({self.uploaded_by.username})"

class SecureFileAccess(models.Model):
    file = models.ForeignKey(SecureFile, on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='securefileaccess_blog_set')
    can_download = models.BooleanField(default=True)
    can_share = models.BooleanField(default=False)
    access_granted_at = models.DateTimeField(auto_now_add=True)
    access_granted_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='granted_file_access_blog', null=True, blank=True)
    last_accessed_at = models.DateTimeField(null=True, blank=True)
    access_count = models.IntegerField(default=0)
    access_expires_at = models.DateTimeField(null=True, blank=True)
    class Meta:
        unique_together = ['file', 'user']
        verbose_name = "Secure File Access (Blog)"
        verbose_name_plural = "Secure File Access Records (Blog)"
    def __str__(self):
        return f"{self.user.username} -> {self.file.original_filename}"

class TemporaryFileShare(models.Model):
    token = models.CharField(max_length=255, unique=True, db_index=True)
    uploader = models.ForeignKey(User, on_delete=models.CASCADE, related_name='temp_shares_blog')
    original_filename = models.CharField(max_length=255)
    file_size = models.BigIntegerField()
    encrypted_data = models.JSONField()
    ephemeral_private_key = models.TextField()
    ephemeral_public_key = models.TextField()
    algorithm = models.CharField(max_length=50, default='AES-256-GCM')
    expires_at = models.DateTimeField()
    max_downloads = models.IntegerField(default=1)
    download_count = models.IntegerField(default=0)
    password_protected = models.BooleanField(default=False)
    share_password = models.CharField(max_length=255, blank=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_accessed = models.DateTimeField(null=True, blank=True)
    class Meta:
        ordering = ['-created_at']
        verbose_name = "Temporary File Share (Blog)"
        verbose_name_plural = "Temporary File Shares (Blog)"
    def __str__(self):
        return f'Temp share: {self.original_filename} ({self.token[:8]}...)'
    def extension(self):
        name, extension = os.path.splitext(self.file.name)
        return extension

    def get_absolute_url(self):
        return reverse('post-detail', kwargs={'pk': self.pk})

    def can_user_access(self, user):
        """Check if a user can access this post based on visibility settings and specific shares"""
        # Check if public sharing is enabled and post is public
        if self.visibility == 'public' and getattr(settings, 'ENABLE_PUBLIC_SHARING', False):
            return True
        elif self.visibility == 'private':
            return user == self.author
        elif self.visibility == 'friends':
            if user == self.author:
                return True
            # Import here to avoid circular imports
            from users.models import Friendship
            return Friendship.are_friends(user, self.author)
        
        # If public sharing is disabled but post is marked public, treat as friends-only
        if self.visibility == 'public' and not getattr(settings, 'ENABLE_PUBLIC_SHARING', False):
            if user == self.author:
                return True
            from users.models import Friendship
            return Friendship.are_friends(user, self.author)
        
        # Check for specific user shares
        if self.shared_with_users.filter(shared_with=user).exists():
            return True
        
        # Check for group shares
        from users.models import UserGroup
        user_groups = UserGroup.objects.filter(members=user, is_active=True)
        if self.shared_with_groups.filter(shared_with_group__in=user_groups).exists():
            return True
        
        return False


