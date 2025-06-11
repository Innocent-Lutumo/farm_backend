from .views import *
from . import views
from django.urls import path, include
from .views import CustomTokenObtainPairView
from rest_framework.routers import DefaultRouter
from .views import TransactionViewSet, SaleTransactionViewSet
from .views import RegisterView, AllFarmsView, FarmDetailView, UploadFarmAPIView
from rest_framework_simplejwt.views import TokenRefreshView


router = DefaultRouter()
router.register(r"rent-transactions", TransactionViewSet, basename="rent-transactions")
router.register(r'sale-transactions', SaleTransactionViewSet, basename='sale-transactions')

urlpatterns = [
    path('admin-login/', views.admin_login, name='admin-login'),
    path('register/', RegisterView.as_view(), name='register'),
    path('admin-sellers/', get_sellers, name='get_sellers'),
    path('admin-sellers-list/', get_sellers_unprotected, name='get_sellers_unprotected'),
    path('admin-sellers/<int:pk>/', views.seller_detail, name='seller_detail'),
    path('UploadFarm/', UploadFarmAPIView.as_view(), name='Upload_farm'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path("login/", CustomTokenObtainPairView.as_view(), name="custom_login"),
    path('google-login/', google_login_view, name='google-login'),
    path('farmsale/', views.get_sale_farms, name='get_farms'),
    path('farmsale/validated/', views.get_validated_sale_farms, name='get_farms'),
    path('farmsale/<int:pk>/update_sold_status/', views.update_farm_sold_status, name='update-farm-sold-status'),
    path('farmsrent/', views.get_rent_farms, name='farms_rent'),
    path('farmsrent/validated/', views.get_validated_rent_farms, name='farms_rent'),
    path('farmsrent/<int:pk>/update_rented_status/', views.update_farm_rented_status, name='update-farm-rented-status'),
    path('farmsale/<int:pk>/', views.FarmSaleDetailAPIView.as_view(), name='farmsale-detail'),
    path('farmsrent/<int:pk>/', views.FarmRentDetailAPIView.as_view(), name='farmsrent-detail'),
    path('farms/<int:id>/', views.sale_farm_detail, name='farm-detail'),
    path('farmrent/<int:id>/', views.rent_farm_detail, name='farm_rent'),
    path('all-farms/', AllFarmsView.as_view(), name='all-farms'),
    path('transactions/', create_rent_transaction, name='create-rent-transaction'),
    path('transactionsale/', create_sale_transaction, name='create-sale-transaction'),
    path('get-transactions/', get_transactions, name='get_transactions'),
    path('get-transactionsale/', sale_transactions, name='sale_transactions'),
    path('send-transaction-email/', send_transaction_email, name='send_transaction_email'),
    path('send-transaction-email-rent/', send_transaction_email_rent, name='send_transaction_email_rent'),
    path('all-farms/<str:farm_type>/<int:farm_id>/', FarmDetailView.as_view(), name='farm_detail'),
    path('download-contract/<int:pk>/', DownloadContractPDFView.as_view(), name='download_contract_pdf'),
    path("", include(router.urls)),
]





