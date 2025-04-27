from .views import *
from . import views
from django.urls import path, include
from .views import CustomTokenObtainPairView
from rest_framework.routers import DefaultRouter
from .views import TransactionViewSet, SaleTransactionViewSet

router = DefaultRouter()
router.register(r"transactions", TransactionViewSet)
router.register(r'sale-transactions', SaleTransactionViewSet, basename='transactions')

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('uploadFarm/', UploadFarmAPIView.as_view(), name='upload_farm'),
    path("login/", CustomTokenObtainPairView.as_view(), name="custom_login"),
    path('google-login/', google_login_view, name='google-login'),
    path('farmsale/', views.get_farms, name='get_farms'),
    path('farmsrent/', views.get_rent_farms, name='farms_rent'),
    path('farms/<int:id>/', views.sale_farm_detail, name='farm-detail'),
    path('farmrent/<int:id>/', views.rent_farm_rent, name='farm_rent'),
    path('all-farms/', AllFarmsView.as_view(), name='all-farms'),
    path('transactions/', create_rent_transaction, name='create-rent-transaction'),
    path('transactionsale/', create_sale_transaction, name='create-sale-transaction'),
    path('get-transactions/', get_transactions, name='get_transactions'),
    path('get-transactionsale/', sale_transactions, name='sale_transactions'),
    path('send-transaction-email/', send_transaction_email, name='send_transaction_email'),
    path("/all-farms/<int:farm_id>/", FarmDetailView.as_view()),
    path("", include(router.urls)),
]





