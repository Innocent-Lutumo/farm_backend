from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.decorators import api_view, permission_classes
from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from django.core.mail import send_mail
from django.conf import settings
from rest_framework.decorators import api_view 
from rest_framework import viewsets
from rest_framework_simplejwt.authentication import JWTAuthentication

from .utils import verify_google_token
from .serializers import (
    RegisterSerializer, 
    CustomTokenObtainPairSerializer, 
    FarmSaleSerializer, 
    FarmRentSerializer, 
    FarmRentTransactionSerializer, 
    FarmSaleTransactionSerializer
)

from .models import (
    FarmSale, FarmRent, 
    FarmImage, 
    FarmRentTransaction, FarmSaleTransaction
)

import json
from google.oauth2 import id_token
from google.auth.transport.requests import Request


class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer

# view for login
class LoginView(APIView):

    def post(self, request):
        username = request.data.get("username")
        password = request.data.get("password")

        if not username or not password:
            return Response({"error": "Username and password are required"}, status=400)

        user = authenticate(request, username=username, password=password)

        if user is None:
            return Response({"error": "Invalid credentials"}, status=401)
        
        refresh = RefreshToken.for_user(user)
        return Response({
            "access": str(refresh.access),
            "refresh": str(refresh)
        })

# view for google login
def verify_google_token(token):
    try:
        id_info = id_token.verify_oauth2_token(token, Request())
        return id_info
    except ValueError:
        return None

@csrf_exempt 
def google_login_view(request):
    if request.method == 'POST':
        try:

            body = json.loads(request.body)
            token = body.get('token')

            if not token:
                return JsonResponse({"error": "Token is missing"}, status=400)

            user_info = verify_google_token(token)
            if not user_info or 'email' not in user_info:
                return JsonResponse({"error": "Invalid token or user info"}, status=400)

            user, created = User.objects.get_or_create(
                username=user_info['email'],
                defaults={
                    'first_name': user_info.get('given_name', ''),
                    'last_name': user_info.get('family_name', '')
                }
            )

            refresh = RefreshToken.for_user(user)
            return JsonResponse({
                "message": "Google login successful",
                "user_info": user_info,
                "access": str(refresh.access),
                "refresh": str(refresh)
            })

        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON"}, status=400)
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)

    return JsonResponse({"error": "Invalid request method"}, status=405)


# view for registration
class RegisterView(APIView):
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "User registered successfully"}, status=201)
        return Response(serializer.errors, status=400)

# view for creating a transaction after click purchase or rent button
@api_view(['POST'])
def create_rent_transaction(request):
    serializer = FarmRentTransactionSerializer(data=request.data)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=201)
    print(serializer.errors)
    return Response(serializer.errors, status=400)


@api_view(['POST'])
def create_sale_transaction(request):
    serializer = FarmSaleTransactionSerializer(data=request.data)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=201)
    return Response(serializer.errors, status=400)

# get already booked farms for both users for confirmation and feedback
@api_view(['GET'])
@permission_classes([AllowAny]) 
def get_transactions(request):
    transactions = FarmRentTransaction.objects.select_related('farm').order_by('rent_date')
    serializer = FarmRentTransactionSerializer(transactions, many=True)
    return Response(serializer.data)

class TransactionViewSet(viewsets.ModelViewSet):
    queryset = FarmRentTransaction.objects.all() 
    serializer_class = FarmRentTransactionSerializer
    permission_classes = [IsAuthenticated]  

    def get_queryset(self):
        return FarmRentTransaction.objects.filter(farm__user=self.request.user)
    

@api_view(['GET'])
def sale_transactions(request):
    transactions = FarmSaleTransaction.objects.select_related('farm').all()
    serializer = FarmSaleTransactionSerializer(transactions, many=True)
    return Response(serializer.data)

class SaleTransactionViewSet(viewsets.ModelViewSet):
    queryset = FarmSaleTransaction.objects.all() 
    serializer_class = FarmSaleTransactionSerializer
    permission_classes = [IsAuthenticated]  

    def get_queryset(self):
        return FarmSaleTransaction.objects.filter(farm__user=self.request.user)

# get the farms lists for sale and rent
@api_view(['GET'])
def get_sale_farms(request):
    farms = FarmSale.objects.all()
    serializer = FarmSaleSerializer(farms, many=True)
    return Response(serializer.data)


@api_view(['GET'])
def get_rent_farms(request):
    farm_type = request.GET.get('type')
    farms = FarmRent.objects.filter(farm_type__iexact=farm_type) if farm_type else FarmRent.objects.all()
    serializer = FarmRentSerializer(farms, many=True)
    return Response(serializer.data)

# get the farm details on new page
@api_view(['GET'])
def sale_farm_detail(request, id):
    try:
        farm = FarmSale.objects.get(pk=id)
    except FarmSale.DoesNotExist:
        return Response({"error": "Farm not found."}, status=404)
    return Response(FarmSaleSerializer(farm).data)


@api_view(['GET'])
def rent_farm_detail(request, id):  
    try:
        farm = FarmRent.objects.get(pk=id)
    except FarmRent.DoesNotExist:
        return Response({"error": "Farm not found."}, status=404)
    return Response(FarmRentSerializer(farm).data)

# upload farm view for authenticated user
class UploadFarmAPIView(APIView):

    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):

        print(f"User authenticated: {request.user.is_authenticated}")
        print(f"User: {request.user}")


        farm_type = request.data.get("farmType")
        images = request.FILES.getlist('images')

        if not (3 <= len(images) <= 10):
            return Response({"error": "Upload between 3 and 10 images."}, status=400)

        serializer = FarmSaleSerializer(data=request.data) if farm_type == "Sale" else (
            FarmRentSerializer(data=request.data) if farm_type == "Rent" else None)

        if not serializer:
            return Response({"error": "Invalid farm type"}, status=400)

        if serializer.is_valid():
            farm = serializer.save(user=request.user) 
            for image in images:
                FarmImage.objects.create(
                    farm_sale=farm if farm_type == "Sale" else None,
                    farm_rent=farm if farm_type == "Rent" else None,
                    image=image
                )
            return Response({"message": f"Farm uploaded successfully for {farm_type}!"}, status=201)

        return Response(serializer.errors, status=400)

# view to render all farms uploaded by that particular user
class AllFarmsView(APIView):

    permission_classes = [IsAuthenticated]

    def get(self, request):
        user=request.user
        sales = FarmSale.objects.filter(user=user)
        rents = FarmRent.objects.filter(user=user)
        combined = [
            {"type": "Sale", "data": FarmSaleSerializer(s).data} for s in sales
        ] + [
            {"type": "Rent", "data": FarmRentSerializer(r).data} for r in rents
        ]
        return Response(combined)

# view to control edit and delete of the farm for all uploaded farms
class FarmDetailView(APIView):
    def get_farm(self, farm_id, farm_type):
        if farm_type == "sale":
            farm = FarmSale.objects.filter(id=farm_id).first()
            return farm, FarmSaleSerializer
        elif farm_type == "rent":
            farm = FarmRent.objects.filter(id=farm_id).first()
            return farm, FarmRentSerializer
        return None, None

    def get(self, request, farm_type, farm_id):
        farm, serializer_class = self.get_farm(farm_id, farm_type)
        if not farm:
            return Response({"error": "Farm not found"}, status=404)
        serializer = serializer_class(farm)
        return Response(serializer.data)

    def put(self, request, farm_type, farm_id):
        farm, serializer_class = self.get_farm(farm_id, farm_type)
        if not farm:
            return Response({"error": "Farm not found"}, status=404)

        serializer = serializer_class(farm, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=400)

    def delete(self, request, farm_type, farm_id):
        farm, _ = self.get_farm(farm_id, farm_type)
        if not farm:
            return Response({"error": "Farm not found"}, status=404)

        farm.delete()
        return Response(status=204)

# view to send transaction ID to the user email
@api_view(['POST'])
def send_transaction_email(request):
    email = request.data.get('buyer_email')
    transaction_id = request.data.get('transaction_id')

    if not email or not transaction_id:
        return Response({'error': 'Missing buyer_email or transaction_id'}, status=400)

    try:
        send_mail(
            'Your Transaction ID from Farm Finder',
            f'Thank you for your purchase! Your transaction ID is: {transaction_id}',
            settings.EMAIL_HOST_USER,
            [email]
        )
        return Response({'message': 'Email sent successfully.'}, status=200)
    except Exception as e:
        return Response({'error': f'Failed to send email: {str(e)}'}, status=500)


@api_view(['POST'])
def send_transaction_email_rent(request):
    email = request.data.get('renter_email')
    transaction_id = request.data.get('transaction_id')

    if not email or not transaction_id:
        return Response({'error': 'Missing renter_email or transaction_id'}, status=400)

    try:
        send_mail(
            'Your Transaction ID from Farm Finder',
            f'Thank you for your rental! Your transaction ID is: {transaction_id}',
            settings.EMAIL_HOST_USER,
            [email]
        )
        return Response({'message': 'Email sent successfully.'}, status=200)
    except Exception as e:
        return Response({'error': f'Failed to send email: {str(e)}'}, status=500)
    

@api_view(['PATCH'])
def update_farm_rent_status(request, id):
    """Update a farm's rental status"""
    try:
        farm = FarmRent.objects.get(pk=id)
        farm.is_rented = request.data.get('is_rented', farm.is_rented)
        farm.save()
        serializer = FarmRentSerializer(farm)
        return Response(serializer.data)
    except FarmRent.DoesNotExist:
        return Response({"error": "Farm not found"}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['PATCH'])
def update_farm_sale_status(request, id):
    """Update a farm's sale status"""
    try:
        farm = FarmSale.objects.get(pk=id)
        farm.is_sold = request.data.get('is_sold', False)
        farm.save()
        serializer = FarmSaleSerializer(farm)
        return Response(serializer.data)
    except FarmSale.DoesNotExist:
        return Response({"error": "Farm not found"}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
@api_view(['GET'])
def get_farm_transactions(request, farm_id):
    """Get all transactions for a specific farm ID"""
    try:
        transactions = FarmRentTransaction.objects.filter(farm_id=farm_id)
        serializer = FarmRentTransactionSerializer(transactions, many=True)
        return Response(serializer.data)
    except Exception as e:
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



