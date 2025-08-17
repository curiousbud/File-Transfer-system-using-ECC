from django.urls import path
from . import views

urlpatterns = [
    path('create/', views.create_temporary_share, name='create-temp-share'),
    path('<str:token>/', views.temp_share_access, name='temp-share-access'),
    path('list/', views.list_temp_shares, name='temp-shares-list'),
]
