from django.db import models
from django.contrib.auth.models import User
from PIL import Image


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
