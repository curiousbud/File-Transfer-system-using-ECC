from django.shortcuts import render, get_object_or_404, redirect
from django.http import HttpResponse, Http404, FileResponse, JsonResponse
from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib import messages
from django.utils import timezone
from django.views.generic import (
    ListView,
    DetailView,
    CreateView,
    UpdateView,
    DeleteView
)
from .models import Post, SecureFile, SecureFileAccess
from users.models import Friendship, ECCKeyPair
import operator
from django.urls import reverse_lazy
from django.contrib.staticfiles.views import serve
import os
from django.conf import settings

from django.db.models import Q

# Import crypto functionality
try:
    from crypto.hybrid_encryption import HybridEncryption
    from crypto.file_handler import SecureFileHandler
    from crypto.ecc_manager import ECCManager
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


@login_required
def home(request):
    # Get all posts that the current user can access
    all_posts = Post.objects.all()
    accessible_posts = []
    
    for post in all_posts:
        if post.can_user_access(request.user):
            accessible_posts.append(post)
    
    context = {
        'posts': accessible_posts
    }
    return render(request, 'blog/home.html', context)

@login_required
def search(request):
    template = 'blog/home.html'
    query = request.GET.get('q')
    
    # Search in posts that user can access
    all_results = Post.objects.filter(
        Q(title__icontains=query) | 
        Q(author__username__icontains=query) | 
        Q(content__icontains=query)
    )
    
    # Filter results based on visibility permissions
    accessible_results = []
    for post in all_results:
        if post.can_user_access(request.user):
            accessible_results.append(post)
    
    context = {'posts': accessible_results}
    return render(request, template, context)
   


def getfile(request):
   return serve(request, 'File')


class PostListView(LoginRequiredMixin, ListView):
    model = Post
    template_name = 'blog/home.html'  # <app>/<model>_<viewtype>.html
    context_object_name = 'posts'
    ordering = ['-date_posted']
    paginate_by = 2

    def get_queryset(self):
        # Get posts that the current user can access
        all_posts = Post.objects.all().order_by('-date_posted')
        accessible_posts = []
        
        for post in all_posts:
            if post.can_user_access(self.request.user):
                accessible_posts.append(post.pk)
        
        return Post.objects.filter(pk__in=accessible_posts).order_by('-date_posted')


class UserPostListView(LoginRequiredMixin, ListView):
    model = Post
    template_name = 'blog/user_posts.html'  # <app>/<model>_<viewtype>.html
    context_object_name = 'posts'
    paginate_by = 2

    def get_queryset(self):
        user = get_object_or_404(User, username=self.kwargs.get('username'))
        user_posts = Post.objects.filter(author=user).order_by('-date_posted')
        
        # Filter posts based on what current user can access
        accessible_posts = []
        for post in user_posts:
            if post.can_user_access(self.request.user):
                accessible_posts.append(post.pk)
        
        return Post.objects.filter(pk__in=accessible_posts).order_by('-date_posted')


class PostDetailView(LoginRequiredMixin, UserPassesTestMixin, DetailView):
    model = Post
    template_name = 'blog/post_detail.html'

    def test_func(self):
        post = self.get_object()
        return post.can_user_access(self.request.user)


class PostCreateView(LoginRequiredMixin, CreateView):
    model = Post
    template_name = 'blog/post_form.html'
    fields = ['title', 'content', 'file', 'visibility']

    def form_valid(self, form):
        form.instance.author = self.request.user
        return super().form_valid(form)


class PostUpdateView(LoginRequiredMixin, UserPassesTestMixin, UpdateView):
    model = Post
    template_name = 'blog/post_form.html'
    fields = ['title', 'content', 'file', 'visibility']

    def form_valid(self, form):
        form.instance.author = self.request.user
        return super().form_valid(form)

    def test_func(self):
        post = self.get_object()
        if self.request.user == post.author:
            return True
        return False


class PostDeleteView(LoginRequiredMixin, UserPassesTestMixin, DeleteView):
    model = Post
    success_url = '/'
    template_name = 'blog/post_confirm_delete.html'

    def test_func(self):
        post = self.get_object()
        if self.request.user == post.author:
            return True
        return False


def about(request):
    return render(request, 'blog/about.html', {'title': 'About'})


@login_required
def secure_file_download(request, pk):
    """
    Secure file download view that requires authentication and friend access
    """
    try:
        post = get_object_or_404(Post, pk=pk)
        
        # Check if user can access this post (friends only restriction)
        if not post.can_user_access(request.user):
            raise Http404("You don't have permission to access this file")
        
        # Check if the post has a file
        if not post.file:
            raise Http404("File not found")
        
        # Get the file path
        file_path = post.file.path
        
        # Check if file exists on disk
        if not os.path.exists(file_path):
            raise Http404("File not found on server")
        
        # Serve the file
        response = FileResponse(
            open(file_path, 'rb'),
            as_attachment=True,
            filename=os.path.basename(file_path)
        )
        
        return response
        
    except Post.DoesNotExist:
        raise Http404("Post not found")
    except Exception as e:
        raise Http404("Error accessing file")


# Secure File Views for Week 3-4 Implementation

@login_required
def secure_file_upload(request):
    """
    Upload and encrypt files for secure sharing
    """
    if not CRYPTO_AVAILABLE:
        messages.error(request, "Cryptographic features are not available.")
        return redirect('blog-home')
    
    if request.method == 'POST':
        try:
            # Get uploaded file
            uploaded_file = request.FILES.get('secure_file')
            if not uploaded_file:
                messages.error(request, "No file selected.")
                return redirect('secure-file-upload')
            
            # Get user's ECC key pair
            try:
                user_keypair = ECCKeyPair.objects.get(user=request.user, is_active=True)
            except ECCKeyPair.DoesNotExist:
                messages.error(request, "You need to generate ECC keys first.")
                return redirect('key-management')
            
            # Get selected friends for sharing
            selected_friends = request.POST.getlist('friends')
            algorithm = request.POST.get('algorithm', 'AES-256-GCM')
            
            # Initialize crypto components
            file_handler = SecureFileHandler()
            hybrid_encryption = HybridEncryption()
            
            # Read file data
            file_data = uploaded_file.read()
            
            # Validate file
            validation = file_handler.validate_file(file_data, uploaded_file.name)
            if not validation['is_valid']:
                messages.error(request, f"File validation failed: {validation['error']}")
                return redirect('secure-file-upload')
            
            # Create SecureFile record
            secure_file = SecureFile.objects.create(
                original_filename=uploaded_file.name,
                file_size=len(file_data),
                file_hash=validation['file_hash'],
                encryption_algorithm=algorithm,
                uploaded_by=request.user
            )
            
            # Encrypt file for each selected friend
            for friend_id in selected_friends:
                try:
                    friend_user = User.objects.get(id=friend_id)
                    friend_keypair = ECCKeyPair.objects.get(user=friend_user, is_active=True)
                    
                    # Get password for decrypting user's private key
                    password = request.POST.get('key_password')
                    if not password:
                        messages.error(request, "Key password is required.")
                        continue
                    
                    # Decrypt user's private key
                    user_private_key = user_keypair.get_decrypted_private_key(password)
                    friend_public_key = friend_keypair.get_public_key()
                    
                    # Encrypt file for this friend
                    if algorithm == 'ChaCha20-Poly1305':
                        encrypted_package = hybrid_encryption.encrypt_file_for_user_chacha20(
                            file_data, friend_public_key, user_private_key, uploaded_file.name
                        )
                    else:  # AES-256-GCM
                        encrypted_package = hybrid_encryption.encrypt_file_for_user(
                            file_data, friend_public_key, user_private_key, uploaded_file.name
                        )
                    
                    # Save encrypted file
                    secure_filename = file_handler.create_secure_filename(
                        f"{secure_file.id}_{friend_user.id}_{uploaded_file.name}"
                    )
                    encrypted_file_path = file_handler.save_encrypted_file(
                        encrypted_package, secure_filename
                    )
                    
                    # Create access record
                    SecureFileAccess.objects.create(
                        secure_file=secure_file,
                        user=friend_user,
                        encrypted_file_path=encrypted_file_path,
                        encryption_metadata=encrypted_package,
                        access_granted_by=request.user
                    )
                    
                except Exception as e:
                    messages.warning(request, f"Failed to encrypt file for {friend_user.username}: {str(e)}")
            
            messages.success(request, f"File '{uploaded_file.name}' encrypted and shared successfully!")
            return redirect('secure-files-list')
            
        except Exception as e:
            messages.error(request, f"File upload failed: {str(e)}")
            return redirect('secure-file-upload')
    
    # GET request - show upload form
    # Get user's friends for sharing options
    friendships = Friendship.objects.filter(
        Q(user1=request.user, status='accepted') | 
        Q(user2=request.user, status='accepted')
    )
    
    friends = []
    for friendship in friendships:
        friend = friendship.user2 if friendship.user1 == request.user else friendship.user1
        # Check if friend has ECC keys
        try:
            ECCKeyPair.objects.get(user=friend, is_active=True)
            friends.append(friend)
        except ECCKeyPair.DoesNotExist:
            continue
    
    context = {
        'friends': friends,
        'supported_algorithms': ['AES-256-GCM', 'ChaCha20-Poly1305']
    }
    return render(request, 'blog/secure_file_upload.html', context)


@login_required
def secure_files_list(request):
    """
    List user's secure files (uploaded and received)
    """
    if not CRYPTO_AVAILABLE:
        messages.error(request, "Cryptographic features are not available.")
        return redirect('blog-home')
    
    # Files uploaded by user
    uploaded_files = SecureFile.objects.filter(uploaded_by=request.user)
    
    # Files shared with user
    received_files = SecureFileAccess.objects.filter(user=request.user)
    
    context = {
        'uploaded_files': uploaded_files,
        'received_files': received_files
    }
    return render(request, 'blog/secure_files_list.html', context)


@login_required
def secure_file_download(request, access_id):
    """
    Download and decrypt a secure file
    """
    if not CRYPTO_AVAILABLE:
        messages.error(request, "Cryptographic features are not available.")
        return redirect('blog-home')
    
    try:
        # Get file access record
        file_access = get_object_or_404(SecureFileAccess, id=access_id, user=request.user)
        secure_file = file_access.secure_file
        
        # Get user's key password
        password = request.POST.get('key_password')
        if not password:
            messages.error(request, "Key password is required for decryption.")
            return redirect('secure-files-list')
        
        # Get user's ECC key pair
        user_keypair = ECCKeyPair.objects.get(user=request.user, is_active=True)
        sender_keypair = ECCKeyPair.objects.get(user=secure_file.uploaded_by, is_active=True)
        
        # Decrypt user's private key
        user_private_key = user_keypair.get_decrypted_private_key(password)
        sender_public_key = sender_keypair.get_public_key()
        
        # Initialize crypto components
        hybrid_encryption = HybridEncryption()
        
        # Decrypt file
        if secure_file.encryption_algorithm == 'ChaCha20-Poly1305':
            decrypted_data = hybrid_encryption.decrypt_file_for_user_chacha20(
                file_access.encryption_metadata, sender_public_key, user_private_key
            )
        else:  # AES-256-GCM
            decrypted_data = hybrid_encryption.decrypt_file_for_user(
                file_access.encryption_metadata, sender_public_key, user_private_key
            )
        
        # Update access count
        file_access.access_count += 1
        file_access.last_accessed = timezone.now()
        file_access.save()
        
        # Serve decrypted file
        response = HttpResponse(
            decrypted_data,
            content_type='application/octet-stream'
        )
        response['Content-Disposition'] = f'attachment; filename="{secure_file.original_filename}"'
        
        return response
        
    except ECCKeyPair.DoesNotExist:
        messages.error(request, "ECC keys not found. Please generate keys first.")
        return redirect('key-management')
    except Exception as e:
        messages.error(request, f"File decryption failed: {str(e)}")
        return redirect('secure-files-list')


@login_required
def secure_file_info(request, file_id):
    """
    Show detailed information about a secure file
    """
    try:
        secure_file = get_object_or_404(SecureFile, id=file_id)
        
        # Check if user has access to this file
        if secure_file.uploaded_by != request.user:
            # Check if file is shared with user
            try:
                file_access = SecureFileAccess.objects.get(
                    secure_file=secure_file, 
                    user=request.user
                )
            except SecureFileAccess.DoesNotExist:
                raise Http404("You don't have access to this file")
        else:
            file_access = None
        
        # Get all access records for this file (if user is owner)
        access_records = []
        if secure_file.uploaded_by == request.user:
            access_records = SecureFileAccess.objects.filter(secure_file=secure_file)
        
        context = {
            'secure_file': secure_file,
            'file_access': file_access,
            'access_records': access_records,
            'is_owner': secure_file.uploaded_by == request.user
        }
        return render(request, 'blog/secure_file_info.html', context)
        
    except Exception as e:
        messages.error(request, f"Error accessing file information: {str(e)}")
        return redirect('secure-files-list')


@login_required
def encryption_benchmark(request):
    """
    Show encryption algorithm benchmarks for educational purposes
    """
    if not CRYPTO_AVAILABLE:
        messages.error(request, "Cryptographic features are not available.")
        return redirect('blog-home')
    
    if request.method == 'POST':
        try:
            from crypto.hybrid_encryption import EncryptionBenchmark
            
            # Run benchmarks
            benchmark = EncryptionBenchmark()
            test_sizes = [1024, 10240, 102400, 1048576]  # 1KB, 10KB, 100KB, 1MB
            results = benchmark.benchmark_algorithms(test_sizes)
            
            context = {
                'benchmark_results': results,
                'test_completed': True
            }
            return render(request, 'blog/encryption_benchmark.html', context)
            
        except Exception as e:
            messages.error(request, f"Benchmark failed: {str(e)}")
    
    context = {'test_completed': False}
    return render(request, 'blog/encryption_benchmark.html', context)
