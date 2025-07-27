from django.urls import path
from .views import (
    PostListView,
    PostDetailView,
    PostCreateView,
    PostUpdateView,
    PostDeleteView,
    UserPostListView
)
from . import views

urlpatterns = [
    path('', PostListView.as_view(), name='blog-home'),
    path('user/<str:username>', UserPostListView.as_view(), name='user-posts'),
    path('post/<int:pk>/', PostDetailView.as_view(), name='post-detail'),
    path('post/new/', PostCreateView.as_view(), name='post-create'),
    path('post/<int:pk>/update/', PostUpdateView.as_view(), name='post-update'),
    path('post/<int:pk>/delete/', PostDeleteView.as_view(), name='post-delete'),
    path('download/<int:pk>/', views.secure_file_download, name='secure-download'),
    path('search/', views.search, name='search'),
    path('about/', views.about, name='blog-about'),
    
    # Week 3-4: Secure File Management URLs
    path('secure-files/upload/', views.secure_file_upload, name='secure-file-upload'),
    path('secure-files/', views.secure_files_list, name='secure-files-list'),
    path('secure-files/download/<int:access_id>/', views.secure_file_download, name='secure-file-download'),
    path('secure-files/info/<int:file_id>/', views.secure_file_info, name='secure-file-info'),
    path('encryption/benchmark/', views.encryption_benchmark, name='encryption-benchmark'),
]
