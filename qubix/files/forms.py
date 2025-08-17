from django import forms
from .models import SecureFile

class SecureFileForm(forms.ModelForm):
    class Meta:
        model = SecureFile
        fields = ['original_filename', 'encrypted_file_path', 'original_size', 'encrypted_size', 'encryption_algorithm', 'curve_name', 'is_chunked', 'file_hash', 'digital_signature', 'metadata', 'expiry_date']
