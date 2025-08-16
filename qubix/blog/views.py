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
from .forms import PostForm, PostUpdateForm
import operator
from django.urls import reverse_lazy
from django.contrib.staticfiles.views import serve
import os
import logging

# Set up logger
logger = logging.getLogger(__name__)
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


def home(request):
    # Get pagination and sorting parameters
    posts_per_page = int(request.GET.get('per_page', 12))  # Default 12 posts
    sort_by = request.GET.get('sort', '-date_posted')  # Default newest first
    filter_author = request.GET.get('author', '')  # Filter by author
    
    # Validate posts per page (limit between 6 and 50)
    posts_per_page = max(6, min(posts_per_page, 50))
    
    # Validate sort options
    allowed_sorts = {
        '-date_posted': 'Newest First',
        'date_posted': 'Oldest First', 
        'title': 'Title A-Z',
        '-title': 'Title Z-A',
        'author__username': 'Author A-Z',
        '-author__username': 'Author Z-A'
    }
    if sort_by not in allowed_sorts:
        sort_by = '-date_posted'
    
    # Get all posts that the current user can access
    all_posts = Post.objects.all()
    accessible_posts = []
    
    for post in all_posts:
        if not request.user.is_authenticated:
            # Show only public posts for anonymous users (if public sharing is enabled)
            if post.visibility == 'public' and getattr(settings, 'ENABLE_PUBLIC_SHARING', False):
                accessible_posts.append(post.pk)
        else:
            if post.can_user_access(request.user):
                accessible_posts.append(post.pk)
    
    # Apply filtering and sorting
    queryset = Post.objects.filter(pk__in=accessible_posts)
    
    # Filter by author if specified
    if filter_author:
        queryset = queryset.filter(author__username__icontains=filter_author)
    
    # Apply sorting
    queryset = queryset.order_by(sort_by)
    
    # Pagination
    from django.core.paginator import Paginator
    paginator = Paginator(queryset, posts_per_page)
    page_number = request.GET.get('page', 1)
    page_obj = paginator.get_page(page_number)
    
    # Get user statistics and recent activity if authenticated
    user_stats = {}
    recent_posts = []
    if request.user.is_authenticated:
        from users.models import UserGroup, GroupMembership
        from datetime import timedelta
        
        # Count secure files
        user_stats['total_files'] = SecureFile.objects.filter(uploaded_by=request.user).count()
        
        # Count friends
        user_friends = Friendship.objects.filter(
            Q(requester=request.user) | Q(addressee=request.user),
            status='accepted'
        )
        user_stats['total_friends'] = user_friends.count()
        
        # Count groups (owned + member of)
        owned_groups = UserGroup.objects.filter(owner=request.user).count()
        member_groups = GroupMembership.objects.filter(
            user=request.user, 
            is_active=True
        ).count()
        user_stats['total_groups'] = owned_groups + member_groups
        
        # Count recent posts (last 30 days)
        recent_date = timezone.now() - timedelta(days=30)
        user_stats['recent_posts'] = Post.objects.filter(
            author=request.user,
            date_posted__gte=recent_date
        ).count()
        
        # Get friend IDs for personalized feed
        friend_users = []
        for friendship in user_friends:
            if friendship.requester == request.user:
                friend_users.append(friendship.addressee)
            else:
                friend_users.append(friendship.requester)
        
        # Get recent posts from friends and user (last 7 days for highlights)
        recent_week = timezone.now() - timedelta(days=7)
        if friend_users:
            recent_posts = Post.objects.filter(
                Q(author__in=friend_users) | Q(author=request.user),
                date_posted__gte=recent_week
            ).order_by('-date_posted')[:6]  # Get 6 most recent posts
    
    # Get all authors for filter dropdown
    all_authors = User.objects.filter(
        post__pk__in=accessible_posts
    ).distinct().order_by('username')
    
    context = {
        'posts': page_obj.object_list,
        'page_obj': page_obj,
        'is_paginated': page_obj.has_other_pages(),
        'recent_posts': recent_posts,
        'user_stats': user_stats if request.user.is_authenticated else None,
        'current_sort': sort_by,
        'sort_options': allowed_sorts,
        'current_per_page': posts_per_page,
        'per_page_options': [6, 12, 24, 36, 50],
        'current_author_filter': filter_author,
        'available_authors': all_authors,
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
    template_name = 'blog/user_posts.html'
    context_object_name = 'posts'
    
    def get_paginate_by(self, queryset):
        # Dynamic pagination based on request parameter
        return int(self.request.GET.get('per_page', 12))
    
    def get_queryset(self):
        user = get_object_or_404(User, username=self.kwargs.get('username'))
        
        # Get sorting parameter
        sort_by = self.request.GET.get('sort', '-date_posted')
        allowed_sorts = {
            '-date_posted': 'Newest First',
            'date_posted': 'Oldest First', 
            'title': 'Title A-Z',
            '-title': 'Title Z-A'
        }
        if sort_by not in allowed_sorts:
            sort_by = '-date_posted'
        
        user_posts = Post.objects.filter(author=user).order_by(sort_by)
        
        # Filter posts based on what current user can access
        accessible_posts = []
        for post in user_posts:
            if post.can_user_access(self.request.user):
                accessible_posts.append(post.pk)
        
        return Post.objects.filter(pk__in=accessible_posts).order_by(sort_by)
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        
        # Add sorting and pagination options to context
        sort_options = {
            '-date_posted': 'Newest First',
            'date_posted': 'Oldest First', 
            'title': 'Title A-Z',
            '-title': 'Title Z-A'
        }
        
        context.update({
            'current_sort': self.request.GET.get('sort', '-date_posted'),
            'sort_options': sort_options,
            'current_per_page': int(self.request.GET.get('per_page', 12)),
            'per_page_options': [6, 12, 24, 36, 50],
        })
        return context


class PostDetailView(LoginRequiredMixin, UserPassesTestMixin, DetailView):
    model = Post
    template_name = 'blog/post_detail.html'

    def test_func(self):
        post = self.get_object()
        return post.can_user_access(self.request.user)


class PostCreateView(LoginRequiredMixin, CreateView):
    model = Post
    form_class = PostForm
    template_name = 'blog/post_form.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        
        # Get user's friends for sharing options
        from users.models import Friendship, UserGroup
        friendships = Friendship.objects.filter(
            Q(requester=self.request.user, status='accepted') | 
            Q(addressee=self.request.user, status='accepted')
        )
        
        friends = []
        for friendship in friendships:
            friend = friendship.addressee if friendship.requester == self.request.user else friendship.requester
            friends.append(friend)
        
        # Get user's groups
        user_groups = UserGroup.objects.filter(
            Q(owner=self.request.user) | Q(members=self.request.user),
            is_active=True
        ).distinct()
        
        context.update({
            'friends': friends,
            'user_groups': user_groups,
        })
        return context

    def form_valid(self, form):
        form.instance.author = self.request.user
        response = super().form_valid(form)
        
        # Handle specific sharing
        self.handle_post_sharing(form.instance)
        
        return response
    
    def handle_post_sharing(self, post):
        """Handle sharing the post with specific users and groups"""
        from .models import PostShare, PostGroupShare
        from users.models import UserGroup
        from django.contrib.auth.models import User
        
        # Get sharing data from POST request
        share_with_friends = self.request.POST.getlist('share_with_friends')
        share_with_groups = self.request.POST.getlist('share_with_groups')
        share_with_search_users = self.request.POST.getlist('share_with_search_users')
        
        # Share with specific friends
        for friend_id in share_with_friends:
            try:
                friend = User.objects.get(id=friend_id)
                PostShare.objects.get_or_create(
                    post=post,
                    shared_with=friend,
                    shared_by=self.request.user
                )
            except User.DoesNotExist:
                continue
        
        # Share with groups
        for group_id in share_with_groups:
            try:
                group = UserGroup.objects.get(id=group_id)
                PostGroupShare.objects.get_or_create(
                    post=post,
                    shared_with_group=group,
                    shared_by=self.request.user
                )
            except UserGroup.DoesNotExist:
                continue
        
        # Share with searched users
        for user_id in share_with_search_users:
            try:
                user = User.objects.get(id=user_id)
                PostShare.objects.get_or_create(
                    post=post,
                    shared_with=user,
                    shared_by=self.request.user
                )
            except User.DoesNotExist:
                continue


class PostUpdateView(LoginRequiredMixin, UserPassesTestMixin, UpdateView):
    model = Post
    form_class = PostUpdateForm
    template_name = 'blog/post_form.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        
        # Get user's friends for sharing options
        from users.models import Friendship, UserGroup
        friendships = Friendship.objects.filter(
            Q(requester=self.request.user, status='accepted') | 
            Q(addressee=self.request.user, status='accepted')
        )
        
        friends = []
        for friendship in friendships:
            friend = friendship.addressee if friendship.requester == self.request.user else friendship.requester
            friends.append(friend)
        
        # Get user's groups
        user_groups = UserGroup.objects.filter(
            Q(owner=self.request.user) | Q(members=self.request.user),
            is_active=True
        ).distinct()
        
        context.update({
            'friends': friends,
            'user_groups': user_groups,
        })
        return context

    def form_valid(self, form):
        form.instance.author = self.request.user
        response = super().form_valid(form)
        
        # Clear existing shares and recreate them
        self.clear_existing_shares(form.instance)
        self.handle_post_sharing(form.instance)
        
        return response
    
    def clear_existing_shares(self, post):
        """Clear existing specific shares for this post"""
        from .models import PostShare, PostGroupShare
        PostShare.objects.filter(post=post).delete()
        PostGroupShare.objects.filter(post=post).delete()
    
    def handle_post_sharing(self, post):
        """Handle sharing the post with specific users and groups"""
        from .models import PostShare, PostGroupShare
        from users.models import UserGroup
        from django.contrib.auth.models import User
        
        # Get sharing data from POST request
        share_with_friends = self.request.POST.getlist('share_with_friends')
        share_with_groups = self.request.POST.getlist('share_with_groups')
        share_with_search_users = self.request.POST.getlist('share_with_search_users')
        
        # Share with specific friends
        for friend_id in share_with_friends:
            try:
                friend = User.objects.get(id=friend_id)
                PostShare.objects.get_or_create(
                    post=post,
                    shared_with=friend,
                    shared_by=self.request.user
                )
            except User.DoesNotExist:
                continue
        
        # Share with groups
        for group_id in share_with_groups:
            try:
                group = UserGroup.objects.get(id=group_id)
                PostGroupShare.objects.get_or_create(
                    post=post,
                    shared_with_group=group,
                    shared_by=self.request.user
                )
            except UserGroup.DoesNotExist:
                continue
        
        # Share with searched users
        for user_id in share_with_search_users:
            try:
                user = User.objects.get(id=user_id)
                PostShare.objects.get_or_create(
                    post=post,
                    shared_with=user,
                    shared_by=self.request.user
                )
            except User.DoesNotExist:
                continue

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
def post_file_download(request, pk):
    """
    Download file attached to a blog post (for legacy posts)
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
            uploaded_file = request.FILES.get('file')
            if not uploaded_file:
                messages.error(request, "No file selected.")
                return redirect('secure-file-upload')
            
            # Get user's ECC key pair
            try:
                user_keypair = ECCKeyPair.objects.get(user=request.user, is_active=True)
            except ECCKeyPair.DoesNotExist:
                messages.error(request, "You need to generate ECC keys first.")
                return redirect('key-management')
            
            # Get selected recipients (friends, groups, and searched users)
            selected_friends = request.POST.getlist('share_with_friends')
            selected_groups = request.POST.getlist('share_with_groups')
            selected_search_users = request.POST.getlist('share_with_search_users')
            algorithm = request.POST.get('encryption_algorithm', 'AES-256-GCM')
            
            # Map algorithm names to model choices
            algorithm_mapping = {
                'AES-256-GCM': 'ECC-AES-256-GCM',
                'ChaCha20-Poly1305': 'ECC-AES-256-GCM'  # Map ChaCha20 to AES for now as model doesn't support ChaCha20
            }
            model_algorithm = algorithm_mapping.get(algorithm, 'ECC-AES-256-GCM')
            
            # Collect all recipient users
            recipients = set()
            
            # Add individual friends
            if selected_friends:
                friends_users = User.objects.filter(id__in=selected_friends)
                recipients.update(friends_users)
            
            # Add group members
            if selected_groups:
                from users.models import UserGroup
                groups = UserGroup.objects.filter(id__in=selected_groups, is_active=True)
                for group in groups:
                    group_members = group.get_members_with_keys()
                    recipients.update(group_members)
            
            # Add searched users
            if selected_search_users:
                search_users = User.objects.filter(id__in=selected_search_users)
                recipients.update(search_users)
            
            # Remove the current user from recipients (can't share with yourself)
            recipients.discard(request.user)
            
            # Initialize crypto components
            file_handler = SecureFileHandler()
            hybrid_encryption = HybridEncryption()
            
            # Read file data
            file_data = uploaded_file.read()
            
            # Validate file
            validation = file_handler.validate_file(file_data, uploaded_file.name)
            if not validation['valid']:
                error_messages = ', '.join(validation['errors']) if validation['errors'] else 'Unknown validation error'
                messages.error(request, f"File validation failed: {error_messages}")
                return redirect('secure-file-upload')
            
            # Create SecureFile record (we'll update it later with encryption details)
            secure_file = SecureFile.objects.create(
                original_filename=uploaded_file.name,
                original_size=len(file_data),
                encrypted_size=0,  # Will be updated after encryption
                file_hash=validation['file_info']['file_hash'],
                encryption_algorithm=model_algorithm,
                encrypted_file_path='',  # Will be updated after encryption
                digital_signature='',  # Will be updated after encryption
                metadata='{}',  # Will be updated with actual metadata
                uploaded_by=request.user
            )
            
            # Encrypt file for each recipient
            for recipient_user in recipients:
                try:
                    recipient_keypair = ECCKeyPair.objects.get(user=recipient_user, is_active=True)
                    
                    # Get password for decrypting user's private key
                    password = request.POST.get('key_password')
                    if not password:
                        messages.error(request, "Key password is required.")
                        continue
                    
                    # Decrypt user's private key
                    user_private_key = user_keypair.get_decrypted_private_key(password)
                    recipient_public_key = recipient_keypair.get_public_key()
                    
                    # Encrypt file for this recipient
                    if algorithm == 'ChaCha20-Poly1305':
                        encrypted_package = hybrid_encryption.encrypt_file_for_user_chacha20(
                            file_data, recipient_public_key, user_private_key, uploaded_file.name
                        )
                    else:  # AES-256-GCM
                        encrypted_package = hybrid_encryption.encrypt_file_for_user(
                            file_data, recipient_public_key, user_private_key, uploaded_file.name
                        )
                    
                    # Save encrypted file
                    secure_filename = file_handler.create_secure_filename(
                        f"{secure_file.id}_{recipient_user.id}_{uploaded_file.name}"
                    )
                    encrypted_file_path = file_handler.save_encrypted_file(
                        encrypted_package, secure_filename
                    )
                    
                    # Create access record
                    SecureFileAccess.objects.create(
                        file=secure_file,
                        user=recipient_user,
                        encrypted_file_path=encrypted_file_path,
                        encryption_metadata=encrypted_package,
                        access_granted_by=request.user
                    )
                    
                except Exception as e:
                    messages.warning(request, f"Failed to encrypt file for {recipient_user.username}: {str(e)}")
            
            messages.success(request, f"File '{uploaded_file.name}' encrypted and shared successfully!")
            return redirect('secure-files-list')
            
        except Exception as e:
            messages.error(request, f"File upload failed: {str(e)}")
            return redirect('secure-file-upload')
    
    # GET request - show upload form
    # Get user's friends for sharing options
    from users.models import UserGroup
    friendships = Friendship.objects.filter(
        Q(requester=request.user, status='accepted') | 
        Q(addressee=request.user, status='accepted')
    )
    
    friends = []
    for friendship in friendships:
        friend = friendship.addressee if friendship.requester == request.user else friendship.requester
        # Check if friend has ECC keys
        try:
            ECCKeyPair.objects.get(user=friend, is_active=True)
            friends.append(friend)
        except ECCKeyPair.DoesNotExist:
            continue
    
    # Get user's groups (both owned and member of)
    user_groups = UserGroup.objects.filter(
        Q(owner=request.user) | Q(members=request.user),
        is_active=True
    ).distinct().prefetch_related('members__ecc_keypair')
    
    # Filter groups to only include those with members who have ECC keys
    valid_groups = []
    for group in user_groups:
        if group.get_members_with_keys().exists():
            valid_groups.append(group)
    
    context = {
        'friends': friends,
        'user_groups': valid_groups,
        'supported_algorithms': ['AES-256-GCM']  # Only show what's actually supported by the model
    }
    return render(request, 'blog/secure_file_upload.html', context)


@login_required
def secure_files_list(request):
    """
    List user's secure files (uploaded and received) with filtering and pagination
    """
    if not CRYPTO_AVAILABLE:
        messages.error(request, "Cryptographic features are not available.")
        return redirect('blog-home')
    
    # Get query parameters for filtering
    search_query = request.GET.get('search', '')
    algorithm_filter = request.GET.get('algorithm', '')
    sort_by = request.GET.get('sort', '-created_at')
    
    # Get file IDs that user has access to (either uploaded by them or shared with them)
    uploaded_file_ids = SecureFile.objects.filter(uploaded_by=request.user).values_list('id', flat=True)
    received_access = SecureFileAccess.objects.filter(user=request.user).values_list('file_id', flat=True)
    
    # Combine all file IDs the user has access to
    all_file_ids = list(uploaded_file_ids) + list(received_access)
    
    # Get all files the user has access to
    all_files = SecureFile.objects.filter(id__in=all_file_ids).distinct()
    
    # Apply filters
    if search_query:
        all_files = all_files.filter(original_filename__icontains=search_query)
    
    if algorithm_filter:
        all_files = all_files.filter(encryption_algorithm=algorithm_filter)
    
    # Apply sorting - map filename to original_filename, created_at to uploaded_at
    sort_mapping = {
        'filename': 'original_filename',
        '-filename': '-original_filename', 
        'created_at': 'uploaded_at',
        '-created_at': '-uploaded_at',
        'file_size': 'original_size',
        '-file_size': '-original_size'
    }
    
    if sort_by in sort_mapping:
        all_files = all_files.order_by(sort_mapping[sort_by])
    else:
        all_files = all_files.order_by('-uploaded_at')
    
    # Calculate statistics
    total_files = all_files.count()
    total_size = sum(f.original_size or 0 for f in all_files)
    total_size_mb = round(total_size / (1024 * 1024), 2) if total_size > 0 else 0
    
    # Calculate shared files (files uploaded by user that have been shared)
    uploaded_files = SecureFile.objects.filter(uploaded_by=request.user)
    shared_files = uploaded_files.filter(securefileaccess__isnull=False).distinct().count()
    
    # Recent files (this week)
    from datetime import datetime, timedelta
    week_ago = timezone.now() - timedelta(days=7)
    recent_files = all_files.filter(uploaded_at__gte=week_ago).count()
    
    # Files received through sharing
    received_access = SecureFileAccess.objects.filter(user=request.user)
    
    context = {
        'files': all_files,
        'total_files': total_files,
        'total_size_mb': total_size_mb,
        'shared_files': shared_files,
        'recent_files': recent_files,
        'uploaded_files': uploaded_files,  # Keep for backward compatibility
        'received_files': received_access,  # Keep for backward compatibility
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
                    file=secure_file, 
                    user=request.user
                )
            except SecureFileAccess.DoesNotExist:
                raise Http404("You don't have access to this file")
        else:
            file_access = None
        
        # Get all access records for this file (if user is owner)
        access_records = []
        if secure_file.uploaded_by == request.user:
            access_records = SecureFileAccess.objects.filter(file=secure_file)
        
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
def secure_file_delete(request, file_id):
    """
    Delete a secure file (only by owner)
    """
    try:
        secure_file = get_object_or_404(SecureFile, id=file_id)
        
        # Check if user is the owner
        if secure_file.uploaded_by != request.user:
            raise Http404("You don't have permission to delete this file")
        
        if request.method == 'POST':
            filename = secure_file.original_filename
            
            try:
                # Delete the physical file if it exists
                if secure_file.encrypted_file_path:
                    file_path = secure_file.encrypted_file_path
                    if os.path.exists(file_path):
                        os.remove(file_path)
                
                # Delete all access records
                SecureFileAccess.objects.filter(file=secure_file).delete()
                
                # Delete the database record
                secure_file.delete()
                
                messages.success(request, f"File '{filename}' has been deleted successfully.")
                logger.info(f"User {request.user.username} deleted secure file: {filename}")
                
            except Exception as e:
                messages.error(request, f"Error deleting file: {str(e)}")
                logger.error(f"Error deleting file {filename} for user {request.user.username}: {str(e)}")
            
            return redirect('secure-files-list')
        
        # GET request - show confirmation
        context = {
            'secure_file': secure_file,
        }
        return render(request, 'blog/secure_file_delete_confirm.html', context)
        
    except Exception as e:
        messages.error(request, f"Error accessing file: {str(e)}")
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


# Phase 5 Enhanced Features: Batch Operations

@login_required
def batch_file_upload(request):
    """
    Upload and encrypt multiple files in batch
    """
    if not CRYPTO_AVAILABLE:
        messages.error(request, "Cryptographic features are not available.")
        return redirect('blog-home')
    
    if request.method == 'POST':
        try:
            from crypto.batch_operations import BatchFileProcessor
            
            # Get uploaded files
            uploaded_files = request.FILES.getlist('batch_files')
            if not uploaded_files:
                messages.error(request, "No files selected for batch upload.")
                return redirect('batch-file-upload')
            
            # Check file count limit
            if len(uploaded_files) > 10:  # Configurable limit
                messages.error(request, "Maximum 10 files allowed per batch operation.")
                return redirect('batch-file-upload')
            
            # Get selected recipients (friends, groups, and searched users)
            selected_friends = request.POST.getlist('friends')
            selected_groups = request.POST.getlist('groups')
            selected_search_users = request.POST.getlist('search_users')
            algorithm = request.POST.get('algorithm', 'AES-256-GCM')
            password = request.POST.get('key_password')
            
            if not password:
                messages.error(request, "Key password is required for batch encryption.")
                return redirect('batch-file-upload')
            
            # Collect all recipient users
            recipients = set()
            
            # Add individual friends
            if selected_friends:
                friends_users = User.objects.filter(id__in=selected_friends)
                recipients.update(friends_users)
            
            # Add group members
            if selected_groups:
                from users.models import UserGroup
                groups = UserGroup.objects.filter(id__in=selected_groups, is_active=True)
                for group in groups:
                    group_members = group.get_members_with_keys()
                    recipients.update(group_members)
            
            # Add searched users
            if selected_search_users:
                search_users = User.objects.filter(id__in=selected_search_users)
                recipients.update(search_users)
            
            # Remove the current user from recipients (can't share with yourself)
            recipients.discard(request.user)
            
            if not recipients:
                messages.error(request, "Please select at least one valid recipient.")
                return redirect('batch-file-upload')
            
            # Convert back to list for compatibility
            recipients = list(recipients)
            
            # Prepare file list
            file_list = []
            total_size = 0
            for uploaded_file in uploaded_files:
                file_data = uploaded_file.read()
                file_size = len(file_data)
                total_size += file_size
                
                # Check individual file size (100MB limit)
                if file_size > 100 * 1024 * 1024:
                    messages.error(request, f"File '{uploaded_file.name}' exceeds 100MB limit.")
                    return redirect('batch-file-upload')
                
                file_list.append({
                    'data': file_data,
                    'filename': uploaded_file.name,
                    'size': file_size
                })
            
            # Check total batch size (500MB limit)
            if total_size > 500 * 1024 * 1024:
                messages.error(request, "Total batch size exceeds 500MB limit.")
                return redirect('batch-file-upload')
            
            # Process batch upload
            processor = BatchFileProcessor(max_workers=4)
            
            import asyncio
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            try:
                results = loop.run_until_complete(
                    processor.batch_encrypt_files(
                        file_list=file_list,
                        sender_user=request.user,
                        recipients=recipients,
                        password=password,
                        algorithm=algorithm
                    )
                )
            finally:
                loop.close()
            
            # Display results
            if results['success_count'] > 0:
                messages.success(
                    request, 
                    f"Batch upload completed! {results['success_count']}/{results['total_files']} "
                    f"files encrypted successfully for {results['total_recipients']} recipients."
                )
            
            if results['error_count'] > 0:
                for error in results['errors'][:3]:  # Show first 3 errors
                    messages.warning(request, f"Error: {error}")
                
                if len(results['errors']) > 3:
                    messages.warning(request, f"...and {len(results['errors']) - 3} more errors.")
            
            return redirect('secure-files-list')
            
        except Exception as e:
            messages.error(request, f"Batch upload failed: {str(e)}")
            return redirect('batch-file-upload')
    
    # GET request - show batch upload form
    # Get user's friends for sharing options
    from users.models import Friendship, UserGroup
    friendships = Friendship.objects.filter(
        Q(requester=request.user, status='accepted') | 
        Q(addressee=request.user, status='accepted')
    )
    
    friends = []
    for friendship in friendships:
        friend = friendship.addressee if friendship.requester == request.user else friendship.requester
        # Check if friend has ECC keys
        try:
            ECCKeyPair.objects.get(user=friend, is_active=True)
            friends.append(friend)
        except ECCKeyPair.DoesNotExist:
            continue
    
    # Get user's groups (both owned and member of)
    user_groups = UserGroup.objects.filter(
        Q(owner=request.user) | Q(members=request.user),
        is_active=True
    ).distinct().prefetch_related('members__ecc_keypair')
    
    # Filter groups to only include those with members who have ECC keys
    valid_groups = []
    for group in user_groups:
        if group.get_members_with_keys().exists():
            valid_groups.append(group)
    
    config_data = {
        'max_files_per_batch': 10,
        'max_file_size_mb': 100,
        'max_batch_size_mb': 500
    }
    
    context = {
        'friends': friends,
        'user_groups': valid_groups,
        'supported_algorithms': ['AES-256-GCM', 'ChaCha20-Poly1305'],
        'max_files_per_batch': config_data['max_files_per_batch'],
        'max_file_size_mb': config_data['max_file_size_mb'],
        'max_batch_size_mb': config_data['max_batch_size_mb'],
        'config_json': config_data
    }
    return render(request, 'blog/batch_file_upload.html', context)


@login_required
def batch_file_download(request):
    """
    Download and decrypt multiple files in batch
    """
    if not CRYPTO_AVAILABLE:
        messages.error(request, "Cryptographic features are not available.")
        return redirect('blog-home')
    
    if request.method == 'POST':
        try:
            from crypto.batch_operations import BatchFileProcessor
            import zipfile
            import io
            
            # Get selected file access IDs
            file_access_ids = request.POST.getlist('file_access_ids')
            password = request.POST.get('key_password')
            
            if not file_access_ids:
                messages.error(request, "No files selected for batch download.")
                return redirect('secure-files-list')
            
            if not password:
                messages.error(request, "Key password is required for batch decryption.")
                return redirect('secure-files-list')
            
            # Limit batch size
            if len(file_access_ids) > 20:
                messages.error(request, "Maximum 20 files allowed per batch download.")
                return redirect('secure-files-list')
            
            # Process batch download
            processor = BatchFileProcessor(max_workers=4)
            
            import asyncio
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            try:
                results = loop.run_until_complete(
                    processor.batch_decrypt_files(
                        file_access_ids=[int(id) for id in file_access_ids],
                        user=request.user,
                        password=password
                    )
                )
            finally:
                loop.close()
            
            # Create ZIP file with decrypted files
            if results['success_count'] > 0:
                zip_buffer = io.BytesIO()
                
                with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
                    for file_result in results['files']:
                        if file_result['status'] == 'success':
                            zip_file.writestr(file_result['filename'], file_result['data'])
                
                zip_buffer.seek(0)
                
                # Serve ZIP file
                response = HttpResponse(
                    zip_buffer.getvalue(),
                    content_type='application/zip'
                )
                response['Content-Disposition'] = f'attachment; filename="qubix_batch_download_{timezone.now().strftime("%Y%m%d_%H%M%S")}.zip"'
                
                messages.success(
                    request,
                    f"Batch download completed! {results['success_count']}/{results['total_files']} files decrypted successfully."
                )
                
                return response
            else:
                messages.error(request, "No files could be decrypted successfully.")
                return redirect('secure-files-list')
            
        except Exception as e:
            messages.error(request, f"Batch download failed: {str(e)}")
            return redirect('secure-files-list')
    
    # GET request - show file selection for batch download
    received_files = SecureFileAccess.objects.filter(user=request.user).select_related('file')
    
    context = {
        'received_files': received_files,
        'max_batch_size': 20
    }
    return render(request, 'blog/batch_file_download.html', context)


@login_required  
def batch_operation_status(request):
    """
    Show status and statistics for batch operations
    """
    try:
        from crypto.batch_operations import BatchFileProcessor
        
        processor = BatchFileProcessor()
        stats = processor.get_batch_processing_stats()
        
        # Get user's recent batch operations (from database logs if implemented)
        recent_uploads = SecureFile.objects.filter(
            uploaded_by=request.user
        ).order_by('-uploaded_at')[:10]
        
        recent_downloads = SecureFileAccess.objects.filter(
            user=request.user,
            last_accessed_at__isnull=False
        ).order_by('-last_accessed_at')[:10]
        
        context = {
            'processor_stats': stats,
            'recent_uploads': recent_uploads,
            'recent_downloads': recent_downloads,
            'user_file_count': SecureFile.objects.filter(uploaded_by=request.user).count(),
            'user_access_count': SecureFileAccess.objects.filter(user=request.user).count()
        }
        return render(request, 'blog/batch_operation_status.html', context)
        
    except Exception as e:
        messages.error(request, f"Error loading batch operation status: {str(e)}")
        return redirect('blog-home')


# API Views

@login_required
def search_users_api(request):
    """
    API endpoint to search for users with ECC keys for file sharing
    """
    if request.method != 'POST':
        return JsonResponse({'error': 'Only POST requests allowed'}, status=405)
    
    try:
        import json
        from django.http import JsonResponse
        
        data = json.loads(request.body)
        search_term = data.get('search_term', '').strip()
        
        if len(search_term) < 2:
            return JsonResponse({'users': []})
        
        # Search for users with ECC keys, excluding current user and existing friends
        from users.models import Friendship
        
        # Get existing friend IDs to exclude them
        friendships = Friendship.objects.filter(
            Q(requester=request.user, status='accepted') | 
            Q(addressee=request.user, status='accepted')
        )
        
        friend_ids = set()
        for friendship in friendships:
            if friendship.requester == request.user:
                friend_ids.add(friendship.addressee.id)
            else:
                friend_ids.add(friendship.requester.id)
        
        # Search users by username or name, exclude current user and friends
        users = User.objects.filter(
            Q(username__icontains=search_term) |
            Q(first_name__icontains=search_term) |
            Q(last_name__icontains=search_term)
        ).exclude(
            id=request.user.id
        ).exclude(
            id__in=friend_ids
        ).filter(
            ecc_keypair__is_active=True
        ).distinct()[:20]  # Limit to 20 results
        
        # Format users for JSON response
        users_data = []
        for user in users:
            full_name = f"{user.first_name} {user.last_name}".strip()
            users_data.append({
                'id': user.id,
                'username': user.username,
                'full_name': full_name if full_name else None,
            })
        
        return JsonResponse({'users': users_data})
        
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


# ============================================================================
# TEMPORARY SHARING FEATURE - Inspired by SecretDrop.io
# ============================================================================

@login_required  
def create_temporary_share(request):
    """
    Create a temporary anonymous sharing link for a file
    """
    if not CRYPTO_AVAILABLE:
        messages.error(request, "Cryptographic features are not available.")
        return redirect('blog-home')
    
    if request.method == 'POST':
        try:
            from .models import TemporaryFileShare
            import uuid
            import os
            from datetime import timedelta
            
            # Get uploaded file
            uploaded_file = request.FILES.get('temp_file')
            if not uploaded_file:
                messages.error(request, "No file selected.")
                return redirect('create-temp-share')
            
            # Get expiration settings
            expiry_hours = int(request.POST.get('expiry_hours', 24))
            max_downloads = int(request.POST.get('max_downloads', 1))
            password_protected = request.POST.get('password_protected') == 'on'
            share_password = request.POST.get('share_password', '')
            
            # Validate settings
            if expiry_hours > 168:  # Max 7 days
                expiry_hours = 168
            if max_downloads > 100:  # Max 100 downloads
                max_downloads = 100
            
            # Generate unique share token
            share_token = str(uuid.uuid4())
            
            # Read and validate file
            file_data = uploaded_file.read()
            if len(file_data) > 50 * 1024 * 1024:  # 50MB limit for temp shares
                messages.error(request, "File too large for temporary sharing (max 50MB).")
                return redirect('create-temp-share')
            
            # Client-side encryption preparation (generate ephemeral key pair)
            from crypto.ecc_manager import ECCManager
            from crypto.curves import get_curve_by_name
            
            curve = get_curve_by_name('P-256')
            ecc_manager = ECCManager(curve)
            ephemeral_private, ephemeral_public = ecc_manager.generate_key_pair()
            
            # Encrypt file with AES-GCM using a random key
            from crypto.hybrid_encryption import HybridEncryption
            hybrid = HybridEncryption()
            
            # Use ephemeral keys for encryption
            encrypted_package = hybrid.encrypt_file_for_user(
                file_data, 
                ephemeral_public, 
                ephemeral_private, 
                uploaded_file.name
            )
            
            # Serialize keys for storage
            private_key_pem = ecc_manager.serialize_private_key(ephemeral_private)
            public_key_pem = ecc_manager.serialize_public_key(ephemeral_public)
            
            # Calculate expiry date
            expiry_date = timezone.now() + timedelta(hours=expiry_hours)
            
            # Create temporary share record
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
            
            # Generate share URLs
            share_url = request.build_absolute_uri(f'/temp-share/{share_token}/')
            
            messages.success(request, f"Temporary share created! Link expires in {expiry_hours} hours.")
            
            context = {
                'temp_share': temp_share,
                'share_url': share_url,
                'expiry_hours': expiry_hours,
                'max_downloads': max_downloads
            }
            return render(request, 'blog/temp_share_created.html', context)
            
        except Exception as e:
            messages.error(request, f"Failed to create temporary share: {str(e)}")
            return redirect('create-temp-share')
    
    # GET request - show form
    context = {
        'max_file_size_mb': 50,
        'default_expiry_hours': 24
    }
    return render(request, 'blog/create_temp_share.html', context)


def temp_share_access(request, token):
    """
    Access a temporary shared file (anonymous access allowed)
    """
    # Check if anonymous temporary sharing is enabled
    if not getattr(settings, 'ENABLE_ANONYMOUS_TEMP_SHARING', True):
        if not request.user.is_authenticated:
            messages.error(request, "You must be logged in to access shared files.")
            return redirect('login')
    
    try:
        from .models import TemporaryFileShare
        
        # Get temporary share
        temp_share = get_object_or_404(TemporaryFileShare, token=token, is_active=True)
        
        # Check if expired
        if temp_share.expires_at < timezone.now():
            temp_share.is_active = False
            temp_share.save()
            raise Http404("Share link has expired")
        
        # Check if max downloads reached
        if temp_share.download_count >= temp_share.max_downloads:
            temp_share.is_active = False
            temp_share.save()
            raise Http404("Download limit reached")
        
        if request.method == 'POST':
            # Handle password if protected
            if temp_share.password_protected:
                provided_password = request.POST.get('share_password', '')
                if provided_password != temp_share.share_password:
                    messages.error(request, "Incorrect password")
                    return render(request, 'blog/temp_share_access.html', {
                        'temp_share': temp_share,
                        'password_required': True
                    })
            
            # Decrypt and serve file
            try:
                from crypto.hybrid_encryption import HybridEncryption
                from crypto.ecc_manager import ECCManager
                from crypto.curves import get_curve_by_name
                
                # Reconstruct ephemeral keys
                curve = get_curve_by_name('P-256')
                ecc_manager = ECCManager(curve)
                
                private_key = ecc_manager.deserialize_private_key(
                    temp_share.ephemeral_private_key.encode('utf-8')
                )
                public_key = ecc_manager.deserialize_public_key(
                    temp_share.ephemeral_public_key.encode('utf-8')
                )
                
                # Decrypt file
                hybrid = HybridEncryption()
                decrypted_data = hybrid.decrypt_file_for_user(
                    temp_share.encrypted_data, 
                    public_key, 
                    private_key
                )
                
                # Update download count
                temp_share.download_count += 1
                temp_share.last_accessed = timezone.now()
                temp_share.save()
                
                # Serve decrypted file
                response = HttpResponse(
                    decrypted_data,
                    content_type='application/octet-stream'
                )
                response['Content-Disposition'] = f'attachment; filename="{temp_share.original_filename}"'
                
                return response
                
            except Exception as e:
                raise Http404("Error decrypting file")
        
        # GET request - show access page
        context = {
            'temp_share': temp_share,
            'password_required': temp_share.password_protected,
            'downloads_remaining': temp_share.max_downloads - temp_share.download_count,
            'expires_in_hours': (temp_share.expires_at - timezone.now()).total_seconds() / 3600
        }
        return render(request, 'blog/temp_share_access.html', context)
        
    except Exception as e:
        raise Http404("Share not found or expired")


@login_required
def list_temp_shares(request):
    """
    List user's temporary shares
    """
    try:
        from .models import TemporaryFileShare
        
        # Get user's temporary shares
        temp_shares = TemporaryFileShare.objects.filter(
            uploader=request.user
        ).order_by('-created_at')
        
        # Clean up expired shares
        expired_shares = temp_shares.filter(
            expires_at__lt=timezone.now(),
            is_active=True
        )
        expired_shares.update(is_active=False)
        
        context = {
            'temp_shares': temp_shares
        }
        return render(request, 'blog/temp_shares_list.html', context)
        
    except Exception as e:
        messages.error(request, f"Error loading temporary shares: {str(e)}")
        return redirect('blog-home')
