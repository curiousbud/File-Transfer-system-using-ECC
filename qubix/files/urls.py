from django.urls import path
from . import views

urlpatterns = [
    path('upload/', views.secure_file_upload, name='secure-file-upload'),
    path('', views.secure_files_list, name='secure-files-list'),
    path('download/<int:access_id>/', views.secure_file_download, name='secure-file-download'),
    path('detail/<int:file_id>/', views.secure_file_info, name='secure-file-detail'),
    path('delete/<int:file_id>/', views.secure_file_delete, name='secure-file-delete'),
]
