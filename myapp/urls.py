from .views import *
from django.urls import path

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('uploadFarm/', UploadFarmAPIView.as_view(), name='upload_farm'),
]


