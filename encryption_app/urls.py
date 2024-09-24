# encryption_app/urls.py

from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='index'),  # Home page
    path('encrypt/', views.encrypt, name='encrypt'),  # Encryption route
    path('decrypt/', views.decrypt, name='decrypt'),  # Decryption route
]
