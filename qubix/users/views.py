from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth import logout
from django.contrib.auth.models import User
from django.http import HttpResponseRedirect, JsonResponse
from django.urls import reverse
from .forms import UserRegisterForm, UserUpdateForm, ProfileUpdateForm
from .models import Profile, Friendship
from django.db.models import Q


def register(request):
    if request.method == 'POST':
        form = UserRegisterForm(request.POST)
        if form.is_valid():
            form.save()
            username = form.cleaned_data.get('username')
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

    context = {
        'u_form': u_form,
        'p_form': p_form
    }

    return render(request, 'users/profile.html', context)


def logout_view(request):
    """
    Custom logout view that properly logs out the user and redirects
    """
    logout(request)
    messages.success(request, 'You have been successfully logged out!')
    return redirect('login')


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
