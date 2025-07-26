from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from PIL import Image
import json


class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    image = models.ImageField(default='default.jpg', upload_to='profile_pics')

    def __str__(self):
        return f'{self.user.username} Profile'

    def save(self, *args, **kwargs):
        super(Profile, self).save(*args, **kwargs)

        img = Image.open(self.image.path)

        if img.height > 300 or img.width > 300:
            output_size = (300, 300)
            img.thumbnail(output_size)
            img.save(self.image.path)


class ECCKeyPair(models.Model):
    """
    Model to store ECC key pairs for each user with secure encryption
    """
    
    CURVE_CHOICES = [
        ('P-256', 'NIST P-256 (Recommended)'),
        ('P-384', 'NIST P-384 (High Security)'),
        ('secp256k1', 'secp256k1 (Bitcoin Curve)'),
    ]
    
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='ecc_keypair')
    
    # Encrypted private key (JSON string containing encrypted package)
    private_key_encrypted = models.TextField(
        help_text="Password-encrypted private key in JSON format"
    )
    
    # Public key (PEM format, safe to store unencrypted)
    public_key = models.TextField(
        help_text="PEM-encoded public key"
    )
    
    # Curve information
    curve_name = models.CharField(
        max_length=20, 
        choices=CURVE_CHOICES, 
        default='P-256',
        help_text="Elliptic curve used for this key pair"
    )
    
    # Key metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)
    key_version = models.IntegerField(default=1)
    
    # Security tracking
    last_used = models.DateTimeField(null=True, blank=True)
    use_count = models.IntegerField(default=0)
    rotation_due_date = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        verbose_name = "ECC Key Pair"
        verbose_name_plural = "ECC Key Pairs"
    
    def __str__(self):
        return f'{self.user.username} - {self.curve_name} (v{self.key_version})'
    
    def get_encrypted_package(self):
        """
        Get the encrypted private key package as a dictionary
        
        Returns:
            dict: Encrypted package data
        """
        try:
            return json.loads(self.private_key_encrypted)
        except json.JSONDecodeError:
            return None
    
    def set_encrypted_package(self, encrypted_package):
        """
        Set the encrypted private key package
        
        Args:
            encrypted_package (dict): Encrypted package from SecureKeyStorage
        """
        self.private_key_encrypted = json.dumps(encrypted_package)
    
    def mark_as_used(self):
        """Mark the key as recently used"""
        self.last_used = timezone.now()
        self.use_count += 1
        self.save(update_fields=['last_used', 'use_count'])
    
    def is_rotation_due(self):
        """
        Check if key rotation is due
        
        Returns:
            bool: True if key should be rotated
        """
        if not self.rotation_due_date:
            return False
        return timezone.now() >= self.rotation_due_date
    
    def set_rotation_due_date(self, days_from_now=90):
        """
        Set when key rotation should be performed
        
        Args:
            days_from_now (int): Days from now when rotation is due
        """
        from datetime import timedelta
        self.rotation_due_date = timezone.now() + timedelta(days=days_from_now)
        self.save(update_fields=['rotation_due_date'])
    
    def get_key_info(self):
        """
        Get comprehensive key information
        
        Returns:
            dict: Key information
        """
        return {
            'user': self.user.username,
            'curve': self.curve_name,
            'version': self.key_version,
            'created': self.created_at,
            'last_used': self.last_used,
            'use_count': self.use_count,
            'is_active': self.is_active,
            'rotation_due': self.is_rotation_due(),
            'days_until_rotation': (self.rotation_due_date - timezone.now()).days if self.rotation_due_date else None
        }


class Friendship(models.Model):
    """
    Model to handle friend relationships between users
    """
    PENDING = 'pending'
    ACCEPTED = 'accepted'
    REJECTED = 'rejected'
    
    STATUS_CHOICES = [
        (PENDING, 'Pending'),
        (ACCEPTED, 'Accepted'),
        (REJECTED, 'Rejected'),
    ]
    
    requester = models.ForeignKey(User, on_delete=models.CASCADE, related_name='friendship_requests_sent')
    addressee = models.ForeignKey(User, on_delete=models.CASCADE, related_name='friendship_requests_received')
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default=PENDING)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ('requester', 'addressee')

    def __str__(self):
        return f'{self.requester.username} -> {self.addressee.username} ({self.status})'

    @staticmethod
    def are_friends(user1, user2):
        """Check if two users are friends"""
        return Friendship.objects.filter(
            models.Q(requester=user1, addressee=user2, status=Friendship.ACCEPTED) |
            models.Q(requester=user2, addressee=user1, status=Friendship.ACCEPTED)
        ).exists()

    @staticmethod
    def get_friends(user):
        """Get all friends of a user"""
        friend_requests = Friendship.objects.filter(
            models.Q(requester=user, status=Friendship.ACCEPTED) |
            models.Q(addressee=user, status=Friendship.ACCEPTED)
        )
        
        friends = []
        for friendship in friend_requests:
            if friendship.requester == user:
                friends.append(friendship.addressee)
            else:
                friends.append(friendship.requester)
        
        return friends


class KeyRotationLog(models.Model):
    """
    Log of key rotation events for audit purposes
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='key_rotations')
    old_key_version = models.IntegerField()
    new_key_version = models.IntegerField()
    rotation_reason = models.CharField(max_length=100, choices=[
        ('scheduled', 'Scheduled Rotation'),
        ('security_breach', 'Security Breach'),
        ('user_request', 'User Request'),
        ('admin_forced', 'Administrator Forced'),
    ])
    rotated_at = models.DateTimeField(auto_now_add=True)
    success = models.BooleanField(default=True)
    notes = models.TextField(blank=True)
    
    class Meta:
        ordering = ['-rotated_at']
    
    def __str__(self):
        return f'{self.user.username} key rotation: v{self.old_key_version} -> v{self.new_key_version}'
