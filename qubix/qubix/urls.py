"""Qubix URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/2.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.contrib.auth import views as auth_views
from django.urls import path, include, re_path
from django.conf import settings
from django.conf.urls.static import static
from django.views.static import serve
from django.http import Http404
from users import views as user_views
import os


def secure_media_serve(request, path):
    """
    Serve media files securely - allow images for display but only to authenticated users
    """
    # Check authentication for all media files except default.jpg
    if path != 'default.jpg' and not request.user.is_authenticated:
        raise Http404("Authentication required")
    
    # Get file extension
    _, ext = os.path.splitext(path.lower())
    
    # Allow these image extensions for display
    allowed_extensions = ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp']
    allowed_files = ['default.jpg']
    
    # Check if it's an allowed image, default file, or profile picture
    if (ext in allowed_extensions or 
        path in allowed_files or 
        path.startswith('profile_pics/') or
        (path.startswith('Files/') and ext in allowed_extensions)):
        
        # For images, serve them normally for display
        document_root = settings.MEDIA_ROOT
        return serve(request, path, document_root=document_root)
    else:
        # For other files (like uploaded documents), raise 404
        # They should be accessed through the secure download view
        raise Http404("File access not allowed")

urlpatterns = [
    path('admin/', admin.site.urls),
    path('login/', auth_views.LoginView.as_view(template_name='users/login.html'), name='login'),
    path('register/', user_views.register, name='register'),
    path('profile/', user_views.profile, name='profile'),
    path('logout/', user_views.logout_view, name='logout'),
    path('', include('blog.urls')),
]

# Serve media files securely - allow images but restrict other file types
if settings.DEBUG:
    # Use our custom secure media serve function
    urlpatterns += [
        re_path(r'^media/(?P<path>.*)$', secure_media_serve, name='media'),
    ]