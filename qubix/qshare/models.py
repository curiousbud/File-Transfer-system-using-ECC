from django.db import models
from django.utils import timezone
from django.contrib.auth.models import User

# Create your models here.
class TemporaryFileShare(models.Model):
	"""
	Model for temporary anonymous file sharing - inspired by SecretDrop.io
	Allows users to share files via anonymous links with expiration and download limits
	"""
	token = models.CharField(max_length=255, unique=True, db_index=True)
	uploader = models.ForeignKey(User, on_delete=models.CASCADE, related_name='temp_shares')
	original_filename = models.CharField(max_length=255)
	file_size = models.BigIntegerField()
	encrypted_data = models.JSONField()
	ephemeral_private_key = models.TextField()  # PEM format
	ephemeral_public_key = models.TextField()   # PEM format
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
		indexes = [
			models.Index(fields=['token', 'is_active']),
			models.Index(fields=['expires_at', 'is_active']),
			models.Index(fields=['uploader', '-created_at']),
		]
	def __str__(self):
		return f'Temp share: {self.original_filename} ({self.token[:8]}...)'
	@property
	def is_expired(self):
		return timezone.now() > self.expires_at
	@property
	def downloads_remaining(self):
		return max(0, self.max_downloads - self.download_count)
	@property
	def hours_until_expiry(self):
		delta = self.expires_at - timezone.now()
		return delta.total_seconds() / 3600
	def deactivate(self):
		self.is_active = False
		self.save()
	def can_download(self):
		return (
			self.is_active and 
			not self.is_expired and 
			self.download_count < self.max_downloads
		)
