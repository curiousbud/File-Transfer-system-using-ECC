from django.shortcuts import render
from django.shortcuts import get_object_or_404, redirect
from django.http import HttpResponse, Http404
from django.contrib import messages
from django.utils import timezone
from django.conf import settings
from django.contrib.auth.decorators import login_required
from .models import SecureFile, SecureFileAccess
from users.models import Friendship, ECCKeyPair, UserGroup
from crypto.file_handler import SecureFileHandler
from crypto.hybrid_encryption import HybridEncryption
import os
from django.db.models import Q

# Create your views here.

@login_required
def secure_file_upload(request):
	# ...existing code from blog/views.py for secure_file_upload...
	# (see migration context for details)
	pass

@login_required
def secure_files_list(request):
	# ...existing code from blog/views.py for secure_files_list...
	pass

@login_required
def secure_file_download(request, access_id):
	# ...existing code from blog/views.py for secure_file_download...
	pass

@login_required
def secure_file_info(request, file_id):
	# ...existing code from blog/views.py for secure_file_info...
	pass

@login_required
def secure_file_delete(request, file_id):
	# ...existing code from blog/views.py for secure_file_delete...
	pass
