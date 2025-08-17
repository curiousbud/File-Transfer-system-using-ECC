from django.contrib import admin
from .models import SecureFile, SecureFileAccess

admin.site.register(SecureFile)
admin.site.register(SecureFileAccess)
