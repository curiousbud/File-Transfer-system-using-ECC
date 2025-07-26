from django.db import models
from django.utils import timezone
from django.contrib.auth.models import User
from django.urls import reverse
import os

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

        
