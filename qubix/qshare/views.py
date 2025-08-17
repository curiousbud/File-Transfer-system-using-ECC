from django.shortcuts import render
from django.shortcuts import get_object_or_404, redirect
from django.http import HttpResponse, Http404
from django.contrib import messages
from django.utils import timezone
from django.conf import settings
from django.contrib.auth.decorators import login_required
from .models import TemporaryFileShare
import uuid
from datetime import timedelta

# Create your views here.

def create_temporary_share(request):
	"""
	Create a temporary anonymous sharing link for a file
	"""
	# You may need to adjust CRYPTO_AVAILABLE import for your app structure
	from crypto.hybrid_encryption import HybridEncryption
	from crypto.ecc_manager import ECCManager
	from crypto.curves import get_curve_by_name
	CRYPTO_AVAILABLE = True
	if not CRYPTO_AVAILABLE:
		messages.error(request, "Cryptographic features are not available.")
		return redirect('qshare-home')
	if request.method == 'POST':
		try:
			uploaded_file = request.FILES.get('temp_file')
			if not uploaded_file:
				messages.error(request, "No file selected.")
				return redirect('create-temp-share')
			expiry_hours = int(request.POST.get('expiry_hours', 24))
			max_downloads = int(request.POST.get('max_downloads', 1))
			password_protected = request.POST.get('password_protected') == 'on'
			share_password = request.POST.get('share_password', '')
			if expiry_hours > 168:
				expiry_hours = 168
			if max_downloads > 100:
				max_downloads = 100
			share_token = str(uuid.uuid4())
			file_data = uploaded_file.read()
			if len(file_data) > 50 * 1024 * 1024:
				messages.error(request, "File too large for temporary sharing (max 50MB).")
				return redirect('create-temp-share')
			curve = get_curve_by_name('P-256')
			ecc_manager = ECCManager(curve)
			ephemeral_private, ephemeral_public = ecc_manager.generate_key_pair()
			hybrid = HybridEncryption()
			encrypted_package = hybrid.encrypt_file_for_user(
				file_data,
				ephemeral_public,
				ephemeral_private,
				uploaded_file.name
			)
			private_key_pem = ecc_manager.serialize_private_key(ephemeral_private)
			public_key_pem = ecc_manager.serialize_public_key(ephemeral_public)
			expiry_date = timezone.now() + timedelta(hours=expiry_hours)
			temp_share = TemporaryFileShare.objects.create(
				token=share_token,
				uploader=request.user,
				original_filename=uploaded_file.name,
				file_size=len(file_data),
				encrypted_data=encrypted_package,
				ephemeral_private_key=private_key_pem.decode('utf-8'),
				ephemeral_public_key=public_key_pem.decode('utf-8'),
				expires_at=expiry_date,
				max_downloads=max_downloads,
				password_protected=password_protected,
				share_password=share_password if password_protected else '',
				algorithm='AES-256-GCM'
			)
			share_url = request.build_absolute_uri(f'/qshare/{share_token}/')
			messages.success(request, f"Temporary share created! Link expires in {expiry_hours} hours.")
			context = {
				'temp_share': temp_share,
				'share_url': share_url,
				'expiry_hours': expiry_hours,
				'max_downloads': max_downloads
			}
			return render(request, 'qshare/temp_share_created.html', context)
		except Exception as e:
			messages.error(request, f"Failed to create temporary share: {str(e)}")
			return redirect('create-temp-share')
	context = {
		'max_file_size_mb': 50,
		'default_expiry_hours': 24
	}
	return render(request, 'qshare/create_temp_share.html', context)

def temp_share_access(request, token):
	"""
	Access a temporary shared file (anonymous access allowed)
	"""
	if not getattr(settings, 'ENABLE_ANONYMOUS_TEMP_SHARING', True):
		if not request.user.is_authenticated:
			messages.error(request, "You must be logged in to access shared files.")
			return redirect('login')
	try:
		temp_share = get_object_or_404(TemporaryFileShare, token=token, is_active=True)
		if temp_share.expires_at < timezone.now():
			temp_share.is_active = False
			temp_share.save()
			raise Http404("Share link has expired")
		if temp_share.download_count >= temp_share.max_downloads:
			temp_share.is_active = False
			temp_share.save()
			raise Http404("Download limit reached")
		if request.method == 'POST':
			if temp_share.password_protected:
				provided_password = request.POST.get('share_password', '')
				if provided_password != temp_share.share_password:
					messages.error(request, "Incorrect password")
					return render(request, 'qshare/temp_share_access.html', {
						'temp_share': temp_share,
						'password_required': True
					})
			try:
				from crypto.hybrid_encryption import HybridEncryption
				from crypto.ecc_manager import ECCManager
				from crypto.curves import get_curve_by_name
				curve = get_curve_by_name('P-256')
				ecc_manager = ECCManager(curve)
				private_key = ecc_manager.deserialize_private_key(
					temp_share.ephemeral_private_key.encode('utf-8')
				)
				public_key = ecc_manager.deserialize_public_key(
					temp_share.ephemeral_public_key.encode('utf-8')
				)
				hybrid = HybridEncryption()
				decrypted_data = hybrid.decrypt_file_for_user(
					temp_share.encrypted_data,
					public_key,
					private_key
				)
				temp_share.download_count += 1
				temp_share.last_accessed = timezone.now()
				temp_share.save()
				response = HttpResponse(
					decrypted_data,
					content_type='application/octet-stream'
				)
				response['Content-Disposition'] = f'attachment; filename="{temp_share.original_filename}"'
				return response
			except Exception as e:
				raise Http404("Error decrypting file")
		context = {
			'temp_share': temp_share,
			'password_required': temp_share.password_protected,
			'downloads_remaining': temp_share.max_downloads - temp_share.download_count,
			'expires_in_hours': (temp_share.expires_at - timezone.now()).total_seconds() / 3600
		}
		return render(request, 'qshare/temp_share_access.html', context)
	except Exception as e:
		raise Http404("Share not found or expired")

@login_required
def list_temp_shares(request):
	"""
	List user's temporary shares
	"""
	try:
		temp_shares = TemporaryFileShare.objects.filter(
			uploader=request.user
		).order_by('-created_at')
		expired_shares = temp_shares.filter(
			expires_at__lt=timezone.now(),
			is_active=True
		)
		expired_shares.update(is_active=False)
		context = {
			'temp_shares': temp_shares
		}
		return render(request, 'qshare/temp_shares_list.html', context)
	except Exception as e:
		messages.error(request, f"Error loading temporary shares: {str(e)}")
		return redirect('qshare-home')
