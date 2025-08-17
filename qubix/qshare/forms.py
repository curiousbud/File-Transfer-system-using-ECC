from django import forms
from .models import TemporaryFileShare

class TemporaryFileShareForm(forms.ModelForm):
    class Meta:
        model = TemporaryFileShare
        fields = ['original_filename', 'file_size', 'expires_at', 'max_downloads', 'password_protected', 'share_password']
