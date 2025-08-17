from django.db import models
from django.utils import timezone
from django.contrib.auth.models import User

import json
import uuid

class SecureFile(models.Model):
	"""
	Model for storing encrypted files using ECC hybrid encryption
	"""
	ENCRYPTION_ALGORITHMS = [
		('ECC-AES-256-GCM', 'ECC + AES-256-GCM'),
		('ECC-AES-256-GCM-CHUNKED', 'ECC + AES-256-GCM (Chunked)'),
	]
	file_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
	original_filename = models.CharField(max_length=255)
	encrypted_file_path = models.CharField(max_length=500)
	original_size = models.BigIntegerField(help_text="Original file size in bytes")
	encrypted_size = models.BigIntegerField(help_text="Encrypted file size in bytes")
	encryption_algorithm = models.CharField(max_length=30, choices=ENCRYPTION_ALGORITHMS)
	curve_name = models.CharField(max_length=20, default='P-256')
	is_chunked = models.BooleanField(default=False)
	file_hash = models.CharField(max_length=64, help_text="SHA-256 hash of original file")
	digital_signature = models.TextField(help_text="Base64-encoded digital signature")
	uploaded_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='uploaded_secure_files')
	allowed_users = models.ManyToManyField(
		User, 
		through='SecureFileAccess', 
		through_fields=('file', 'user'),
		related_name='accessible_secure_files'
	)
	metadata = models.TextField(help_text="JSON-encoded file metadata")
	uploaded_at = models.DateTimeField(auto_now_add=True)
	last_accessed = models.DateTimeField(null=True, blank=True)
	access_count = models.IntegerField(default=0)
	is_active = models.BooleanField(default=True)
	expiry_date = models.DateTimeField(null=True, blank=True)
	class Meta:
		verbose_name = "Secure File"
		verbose_name_plural = "Secure Files"
		ordering = ['-uploaded_at']
	def __str__(self):
		return f"{self.original_filename} ({self.uploaded_by.username})"
	def get_metadata(self):
		try:
			return json.loads(self.metadata)
		except json.JSONDecodeError:
			return {}
	def set_metadata(self, metadata_dict):
		self.metadata = json.dumps(metadata_dict)
	def mark_accessed(self, user=None):
		self.last_accessed = timezone.now()
		self.access_count += 1
		self.save(update_fields=['last_accessed', 'access_count'])
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
		if not user.is_authenticated:
			return False
		if user == self.uploaded_by:
			return True
		return self.allowed_users.filter(id=user.id).exists()
	def is_expired(self):
		if self.expiry_date:
			return timezone.now() > self.expiry_date
		return False
	def get_file_size_display(self):
		size = self.original_size
		for unit in ['B', 'KB', 'MB', 'GB']:
			if size < 1024:
				return f"{size:.1f} {unit}"
			size /= 1024
		return f"{size:.1f} TB"
	def get_encryption_info(self):
		return {
			'algorithm': self.get_encryption_algorithm_display(),
			'curve': self.curve_name,
			'chunked': self.is_chunked,
			'file_hash': self.file_hash[:16] + '...',
			'has_signature': bool(self.digital_signature)
		}

class SecureFileAccess(models.Model):
	"""
	Through model for tracking user access to secure files
	"""
	file = models.ForeignKey(SecureFile, on_delete=models.CASCADE)
	user = models.ForeignKey(User, on_delete=models.CASCADE)
	can_download = models.BooleanField(default=True)
	can_share = models.BooleanField(default=False)
	access_granted_at = models.DateTimeField(auto_now_add=True)
	access_granted_by = models.ForeignKey(
		User, 
		on_delete=models.CASCADE, 
		related_name='granted_file_access',
		null=True, 
		blank=True
	)
	last_accessed_at = models.DateTimeField(null=True, blank=True)
	access_count = models.IntegerField(default=0)
	access_expires_at = models.DateTimeField(null=True, blank=True)
	class Meta:
		unique_together = ['file', 'user']
		verbose_name = "Secure File Access"
		verbose_name_plural = "Secure File Access Records"
	def __str__(self):
		return f"{self.user.username} -> {self.file.original_filename}"
	def is_access_expired(self):
		if self.access_expires_at:
			return timezone.now() > self.access_expires_at
		return False
	def can_access(self):
		if self.is_access_expired():
			return False
		if not self.file.is_active:
			return False
		if self.file.is_expired():
			return False
		return True
from django.db import models

# Create your models here.
