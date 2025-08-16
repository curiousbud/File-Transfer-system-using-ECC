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
    path('', views.home, name='blog-home'),
    path('posts/', PostListView.as_view(), name='post-list'),
    path('user/<str:username>', UserPostListView.as_view(), name='user-posts'),
    path('post/<int:pk>/', PostDetailView.as_view(), name='post-detail'),
    path('post/new/', PostCreateView.as_view(), name='post-create'),
    path('post/<int:pk>/update/', PostUpdateView.as_view(), name='post-update'),
    path('post/<int:pk>/delete/', PostDeleteView.as_view(), name='post-delete'),
    path('download/<int:pk>/', views.post_file_download, name='post-file-download'),
    path('search/', views.search, name='search'),
    path('about/', views.about, name='blog-about'),
    
    # Week 3-4: Secure File Management URLs
    path('secure-files/upload/', views.secure_file_upload, name='secure-file-upload'),
    path('secure-files/', views.secure_files_list, name='secure-files-list'),
    path('secure-files/download/<int:access_id>/', views.secure_file_download, name='secure-file-download'),
    path('secure-files/detail/<int:file_id>/', views.secure_file_info, name='secure-file-detail'),
    path('secure-files/delete/<int:file_id>/', views.secure_file_delete, name='secure-file-delete'),
    path('encryption/benchmark/', views.encryption_benchmark, name='encryption-benchmark'),
    
    # Phase 5: Enhanced Features - Batch Operations
    path('batch/upload/', views.batch_file_upload, name='batch-upload'),
    path('batch/download/', views.batch_file_download, name='batch-download'),
    path('batch/status/', views.batch_operation_status, name='batch-status'),
    
    # Temporary Sharing Feature (Anonymous Access)
    path('temp-share/create/', views.create_temporary_share, name='create-temp-share'),
    path('temp-share/<str:token>/', views.temp_share_access, name='temp-share-access'),
    path('temp-shares/', views.list_temp_shares, name='temp-shares-list'),
    
    # API endpoints
    path('api/search-users/', views.search_users_api, name='search-users-api'),
]
