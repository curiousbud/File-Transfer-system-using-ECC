from django.shortcuts import render, get_object_or_404
from django.http import HttpResponse, Http404, FileResponse
from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.views.generic import (
    ListView,
    DetailView,
    CreateView,
    UpdateView,
    DeleteView
)
from .models import Post
from users.models import Friendship
import operator
from django.urls import reverse_lazy
from django.contrib.staticfiles.views import serve
import os
from django.conf import settings

from django.db.models import Q


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
