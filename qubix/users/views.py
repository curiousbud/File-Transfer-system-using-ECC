from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth import logout
from django.contrib.auth.models import User
from django.http import HttpResponseRedirect, JsonResponse
from django.urls import reverse
from django.utils import timezone
from .forms import UserRegisterForm, UserUpdateForm, ProfileUpdateForm
from .models import Profile, Friendship, ECCKeyPair, KeyRotationLog
from django.db.models import Q

# Import crypto modules with error handling
try:
    from crypto.ecc_manager import ECCManager
    from crypto.key_storage import SecureKeyStorage
    from crypto.curves import SupportedCurves, get_curve_by_name
    CRYPTO_AVAILABLE = True
except ImportError as e:
    CRYPTO_AVAILABLE = False
    print(f"Warning: Crypto modules not available: {e}")


def register(request):
    if request.method == 'POST':
        form = UserRegisterForm(request.POST)
        if form.is_valid():
            user = form.save()
            username = form.cleaned_data.get('username')
            
            # Generate ECC key pair for new user if crypto is available
            if CRYPTO_AVAILABLE:
                try:
                    generate_user_key_pair(user, 'defaultpassword123')  # Temporary password
                    messages.success(request, f'Your account has been created with secure ECC keys! You are now able to log in')
                except Exception as e:
                    messages.warning(request, f'Account created but key generation failed: {str(e)}')
            else:
                messages.success(request, f'Your account has been created! You are now able to log in')
            
            return redirect('login')
    else:
        form = UserRegisterForm()
    return render(request, 'users/register.html', {'form': form})


@login_required
def profile(request):
    if request.method == 'POST':
        u_form = UserUpdateForm(request.POST, instance=request.user)
        p_form = ProfileUpdateForm(request.POST,
                                   request.FILES,
                                   instance=request.user.profile)
        if u_form.is_valid() and p_form.is_valid():
            u_form.save()
            p_form.save()
            messages.success(request, f'Your account has been updated!')
            return redirect('profile')

    else:
        u_form = UserUpdateForm(instance=request.user)
        p_form = ProfileUpdateForm(instance=request.user.profile)

    # Get ECC key information
    ecc_key_info = None
    if CRYPTO_AVAILABLE:
        try:
            ecc_keypair = ECCKeyPair.objects.get(user=request.user)
            ecc_key_info = ecc_keypair.get_key_info()
        except ECCKeyPair.DoesNotExist:
            ecc_key_info = None

    context = {
        'u_form': u_form,
        'p_form': p_form,
        'ecc_key_info': ecc_key_info,
        'crypto_available': CRYPTO_AVAILABLE
    }

    return render(request, 'users/profile.html', context)


def logout_view(request):
    """
    Custom logout view that properly logs out the user and redirects
    """
    logout(request)
    messages.success(request, 'You have been successfully logged out!')
    return redirect('login')


# ECC Key Management Functions
def generate_user_key_pair(user, password, curve_name='P-256'):
    """
    Generate ECC key pair for a user
    
    Args:
        user: Django User instance
        password: Password to encrypt the private key
        curve_name: Name of the curve to use
        
    Returns:
        ECCKeyPair: Created key pair instance
    """
    if not CRYPTO_AVAILABLE:
        raise RuntimeError("Cryptographic libraries not available")
    
    try:
        # Get curve
        curve = get_curve_by_name(curve_name)
        
        # Generate key pair
        ecc_manager = ECCManager(curve)
        private_key, public_key = ecc_manager.generate_key_pair()
        
        # Serialize keys
        private_key_pem = ecc_manager.serialize_private_key(private_key)
        public_key_pem = ecc_manager.serialize_public_key(public_key)
        
        # Encrypt private key
        key_storage = SecureKeyStorage()
        encrypted_package = key_storage.encrypt_private_key(private_key_pem, password)
        
        # Create or update ECCKeyPair instance
        ecc_keypair, created = ECCKeyPair.objects.get_or_create(
            user=user,
            defaults={
                'curve_name': curve_name,
                'public_key': public_key_pem.decode('utf-8'),
                'key_version': 1
            }
        )
        
        if not created:
            # Update existing key pair (rotation)
            ecc_keypair.key_version += 1
            
            # Log the rotation
            KeyRotationLog.objects.create(
                user=user,
                old_key_version=ecc_keypair.key_version - 1,
                new_key_version=ecc_keypair.key_version,
                rotation_reason='user_request',
                success=True
            )
        
        ecc_keypair.set_encrypted_package(encrypted_package)
        ecc_keypair.public_key = public_key_pem.decode('utf-8')
        ecc_keypair.curve_name = curve_name
        ecc_keypair.is_active = True
        ecc_keypair.set_rotation_due_date()
        ecc_keypair.save()
        
        return ecc_keypair
        
    except Exception as e:
        # Log failed rotation if this was an update
        if not created:
            KeyRotationLog.objects.create(
                user=user,
                old_key_version=ecc_keypair.key_version,
                new_key_version=ecc_keypair.key_version,
                rotation_reason='user_request',
                success=False,
                notes=str(e)
            )
        raise


@login_required
def key_management(request):
    """Key management dashboard"""
    if not CRYPTO_AVAILABLE:
        messages.error(request, "Cryptographic features are not available.")
        return redirect('profile')
    
    try:
        ecc_keypair = ECCKeyPair.objects.get(user=request.user)
        key_info = ecc_keypair.get_key_info()
    except ECCKeyPair.DoesNotExist:
        ecc_keypair = None
        key_info = None
    
    # Get rotation history
    rotation_history = KeyRotationLog.objects.filter(user=request.user)[:5]
    
    # Get available curves
    available_curves = []
    for curve in SupportedCurves.get_all_curves():
        available_curves.append({
            'name': curve.value['name'],
            'description': curve.value['description'],
            'security_level': curve.value['security_level'],
            'recommended': curve.value['recommended']
        })
    
    context = {
        'ecc_keypair': ecc_keypair,
        'key_info': key_info,
        'rotation_history': rotation_history,
        'available_curves': available_curves,
        'crypto_available': CRYPTO_AVAILABLE
    }

    return render(request, 'users/key_management.html', context)
@login_required
def generate_keys(request):
    """Generate new ECC key pair"""
    if not CRYPTO_AVAILABLE:
        messages.error(request, "Cryptographic features are not available.")
        return redirect('profile')
    
    if request.method == 'POST':
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')
        curve_name = request.POST.get('curve', 'P-256')
        
        if not password:
            messages.error(request, "Password is required for key encryption.")
            return redirect('key-management')
        
        if password != confirm_password:
            messages.error(request, "Passwords do not match.")
            return redirect('key-management')
        
        # Check password strength
        key_storage = SecureKeyStorage()
        strength_info = key_storage.get_key_strength_info(password)
        
        if strength_info['strength_level'] in ['very_weak', 'weak']:
            messages.warning(request, 
                f"Password strength is {strength_info['strength_level']}. "
                "Consider using a stronger password for better security.")
        
        try:
            ecc_keypair = generate_user_key_pair(request.user, password, curve_name)
            
            if ECCKeyPair.objects.filter(user=request.user).count() > 1:
                messages.success(request, f"ECC key pair rotated successfully! New version: {ecc_keypair.key_version}")
            else:
                messages.success(request, f"ECC key pair generated successfully using {curve_name} curve!")
            
        except Exception as e:
            messages.error(request, f"Failed to generate key pair: {str(e)}")
    
    return redirect('key-management')


@login_required
def rotate_keys(request):
    """Rotate existing ECC key pair"""
    if not CRYPTO_AVAILABLE:
        messages.error(request, "Cryptographic features are not available.")
        return redirect('profile')
    
    if request.method == 'POST':
        try:
            ecc_keypair = ECCKeyPair.objects.get(user=request.user)
        except ECCKeyPair.DoesNotExist:
            messages.error(request, "No existing key pair found. Please generate keys first.")
            return redirect('key-management')
        
        password = request.POST.get('password')
        new_curve = request.POST.get('curve', ecc_keypair.curve_name)
        
        if not password:
            messages.error(request, "Password is required for key rotation.")
            return redirect('key-management')
        
        try:
            # Verify current password works
            key_storage = SecureKeyStorage()
            encrypted_package = ecc_keypair.get_encrypted_package()
            
            if not key_storage.verify_password(encrypted_package, password):
                messages.error(request, "Incorrect password.")
                return redirect('key-management')
            
            # Generate new key pair
            new_keypair = generate_user_key_pair(request.user, password, new_curve)
            messages.success(request, f"Keys rotated successfully! New version: {new_keypair.key_version}")
            
        except Exception as e:
            messages.error(request, f"Key rotation failed: {str(e)}")
    
    return redirect('key-management')


@login_required
def key_info_api(request):
    """API endpoint for key information"""
    if not CRYPTO_AVAILABLE:
        return JsonResponse({
            'error': 'Cryptographic features not available',
            'available': False
        }, status=503)
    
    if not request.user.is_authenticated:
        return JsonResponse({
            'error': 'Authentication required'
        }, status=401)
    
    try:
        ecc_keypair = ECCKeyPair.objects.get(user=request.user)
        key_info = ecc_keypair.get_key_info()
        
        # Convert datetime objects to strings for JSON serialization
        for key, value in key_info.items():
            if hasattr(value, 'isoformat'):
                key_info[key] = value.isoformat()
        
        return JsonResponse({
            'success': True,
            'user': request.user.username,
            'key_info': key_info
        })
        
    except ECCKeyPair.DoesNotExist:
        return JsonResponse({
            'error': 'No key pair found',
            'message': 'User has not generated an ECC key pair yet',
            'user': request.user.username,
            'suggestion': 'Generate a key pair first at /keys/generate/'
        }, status=200)  # Changed from 404 to 200 for better UX


@login_required
def user_search(request):
    """Search for users to add as friends"""
    query = request.GET.get('q', '')
    users = []
    
    if query:
        users = User.objects.filter(
            Q(username__icontains=query) | Q(first_name__icontains=query) | Q(last_name__icontains=query)
        ).exclude(id=request.user.id)
    
    # Add friendship status for each user
    user_data = []
    for user in users:
        friendship_status = 'none'
        existing_friendship = Friendship.objects.filter(
            Q(requester=request.user, addressee=user) |
            Q(requester=user, addressee=request.user)
        ).first()
        
        if existing_friendship:
            if existing_friendship.status == Friendship.ACCEPTED:
                friendship_status = 'friends'
            elif existing_friendship.status == Friendship.PENDING:
                if existing_friendship.requester == request.user:
                    friendship_status = 'request_sent'
                else:
                    friendship_status = 'request_received'
            elif existing_friendship.status == Friendship.REJECTED:
                friendship_status = 'rejected'
        
        user_data.append({
            'user': user,
            'friendship_status': friendship_status
        })
    
    context = {
        'users': user_data,
        'query': query
    }
    return render(request, 'users/user_search.html', context)


@login_required
def send_friend_request(request, user_id):
    """Send a friend request to another user"""
    if request.method == 'POST':
        addressee = get_object_or_404(User, id=user_id)
        
        if addressee == request.user:
            messages.error(request, "You cannot send a friend request to yourself.")
            return redirect('user-search')
        
        # Check if friendship already exists
        existing_friendship = Friendship.objects.filter(
            Q(requester=request.user, addressee=addressee) |
            Q(requester=addressee, addressee=request.user)
        ).first()
        
        if existing_friendship:
            if existing_friendship.status == Friendship.ACCEPTED:
                messages.info(request, f"You are already friends with {addressee.username}.")
            elif existing_friendship.status == Friendship.PENDING:
                messages.info(request, f"Friend request already sent to {addressee.username}.")
            else:
                messages.info(request, f"Previous friend request with {addressee.username} was rejected.")
        else:
            # Create new friendship request
            Friendship.objects.create(
                requester=request.user,
                addressee=addressee,
                status=Friendship.PENDING
            )
            messages.success(request, f"Friend request sent to {addressee.username}!")
    
    return redirect('user-search')


@login_required
def manage_friend_request(request, friendship_id, action):
    """Accept or reject a friend request"""
    if request.method == 'POST':
        friendship = get_object_or_404(Friendship, id=friendship_id, addressee=request.user)
        
        if action == 'accept':
            friendship.status = Friendship.ACCEPTED
            friendship.save()
            messages.success(request, f"You are now friends with {friendship.requester.username}!")
        elif action == 'reject':
            friendship.status = Friendship.REJECTED
            friendship.save()
            messages.info(request, f"Friend request from {friendship.requester.username} rejected.")
    
    return redirect('friend-requests')


@login_required
def friend_requests(request):
    """View pending friend requests"""
    pending_requests = Friendship.objects.filter(
        addressee=request.user,
        status=Friendship.PENDING
    ).order_by('-created_at')
    
    context = {
        'pending_requests': pending_requests
    }
    return render(request, 'users/friend_requests.html', context)


@login_required
def friends_list(request):
    """View list of friends"""
    friends = Friendship.get_friends(request.user)
    
    context = {
        'friends': friends
    }
    return render(request, 'users/friends_list.html', context)


@login_required
def remove_friend(request, user_id):
    """Remove a friend"""
    if request.method == 'POST':
        friend = get_object_or_404(User, id=user_id)
        
        # Find and delete the friendship
        friendship = Friendship.objects.filter(
            Q(requester=request.user, addressee=friend, status=Friendship.ACCEPTED) |
            Q(requester=friend, addressee=request.user, status=Friendship.ACCEPTED)
        ).first()
        
        if friendship:
            friendship.delete()
            messages.success(request, f"You are no longer friends with {friend.username}.")
        else:
            messages.error(request, f"You are not friends with {friend.username}.")
    
    return redirect('friends-list')


# User Group Management Views

@login_required
def groups_list(request):
    """List user's groups"""
    from .models import UserGroup
    
    # Groups owned by user
    owned_groups = UserGroup.objects.filter(owner=request.user, is_active=True)
    
    # Groups user is a member of
    member_groups = UserGroup.objects.filter(
        members=request.user, 
        is_active=True
    ).exclude(owner=request.user)
    
    context = {
        'owned_groups': owned_groups,
        'member_groups': member_groups,
    }
    return render(request, 'users/groups_list.html', context)


@login_required
def create_group(request):
    """Create a new user group"""
    from .models import UserGroup, GroupMembership
    
    if request.method == 'POST':
        name = request.POST.get('name')
        description = request.POST.get('description', '')
        selected_members = request.POST.getlist('members')
        
        if not name:
            messages.error(request, "Group name is required.")
            return redirect('create-group')
        
        # Check if group name already exists for this user
        if UserGroup.objects.filter(owner=request.user, name=name).exists():
            messages.error(request, "You already have a group with this name.")
            return redirect('create-group')
        
        try:
            # Create the group
            group = UserGroup.objects.create(
                name=name,
                description=description,
                owner=request.user
            )
            
            # Add selected members
            for member_id in selected_members:
                try:
                    member_user = User.objects.get(id=member_id)
                    GroupMembership.objects.create(
                        user=member_user,
                        group=group,
                        role=GroupMembership.MEMBER
                    )
                except User.DoesNotExist:
                    continue
            
            messages.success(request, f"Group '{name}' created successfully with {len(selected_members)} members.")
            return redirect('groups-list')
            
        except Exception as e:
            messages.error(request, f"Failed to create group: {str(e)}")
    
    # GET request - show form
    # Get user's friends to add to group
    friends = Friendship.get_friends(request.user)
    # Filter friends with ECC keys
    friends_with_keys = []
    for friend in friends:
        try:
            ECCKeyPair.objects.get(user=friend, is_active=True)
            friends_with_keys.append(friend)
        except ECCKeyPair.DoesNotExist:
            continue
    
    context = {
        'friends': friends_with_keys,
    }
    return render(request, 'users/create_group.html', context)


@login_required
def group_detail(request, group_id):
    """View group details and manage members"""
    from .models import UserGroup, GroupMembership
    
    group = get_object_or_404(UserGroup, id=group_id, is_active=True)
    
    # Check if user has access to this group
    if group.owner != request.user and not group.members.filter(id=request.user.id).exists():
        messages.error(request, "You don't have access to this group.")
        return redirect('groups-list')
    
    # Get group memberships
    memberships = GroupMembership.objects.filter(group=group, is_active=True).select_related('user')
    
    # Check if user can edit (is owner or admin)
    user_membership = GroupMembership.objects.filter(group=group, user=request.user, is_active=True).first()
    can_edit = group.owner == request.user or (user_membership and user_membership.role == GroupMembership.ADMIN)
    
    context = {
        'group': group,
        'memberships': memberships,
        'can_edit': can_edit,
        'is_owner': group.owner == request.user,
    }
    return render(request, 'users/group_detail.html', context)
