from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.decorators import api_view, permission_classes
from django.contrib.auth import authenticate
from django.contrib.auth.models import User, Group
from django.contrib.auth import get_user_model
from django.views.decorators.csrf import csrf_exempt
from rest_framework.authtoken.models import Token
from django.http import JsonResponse, HttpResponse
from django.shortcuts import get_object_or_404
from django.core.mail import send_mail
from django.db.models import Q
from django.conf import settings
from rest_framework.decorators import api_view, action
from rest_framework import viewsets
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework import generics

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
import traceback
from google.oauth2 import id_token
from google.auth.transport.requests import Request

# token generation view for sellers
class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer

# view to get the list of all sellers
User = get_user_model()

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_sellers(request):
    user = request.user
    if not (user.is_superuser or user.groups.filter(name='Admin').exists()):
        return Response({'error': 'User is not an admin.'}, status=status.HTTP_403_FORBIDDEN)
    
    sellers = User.objects.filter(groups__name='Seller')
    if not sellers.exists():
        return Response({'message': 'No sellers found.'}, status=status.HTTP_404_NOT_FOUND)
    
    serializer = RegisterSerializer(sellers, many=True)
    return Response(serializer.data)

@api_view(['GET', 'PUT', 'DELETE'])
@permission_classes([IsAuthenticated])
def seller_detail(request, pk):
    """
    Get, update or delete a specific seller.
    """
    user = request.user
    if not (user.is_superuser or user.groups.filter(name='Admin').exists()):
        return Response({'error': 'User is not an admin.'}, status=status.HTTP_403_FORBIDDEN)
    
    try:
        seller = User.objects.get(pk=pk)
        # Check if user is in Seller group
        if not seller.groups.filter(name='Seller').exists():
            return Response({'error': 'User is not a seller.'}, status=status.HTTP_400_BAD_REQUEST)
    except User.DoesNotExist:
        return Response({'error': 'Seller not found.'}, status=status.HTTP_404_NOT_FOUND)
    
    # GET request to retrieve seller details
    if request.method == 'GET':
        serializer = RegisterSerializer(seller)
        return Response(serializer.data)
    
    # PUT request to update seller details
    elif request.method == 'PUT':
        serializer = RegisterSerializer(seller, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    # DELETE request to remove a seller
    elif request.method == 'DELETE':
        # Option 1: Complete deletion (use with caution)
        # seller.delete()
        
        # Option 2: Safer option - remove from Seller group but keep the user
        seller_group = seller.groups.get(name='Seller')
        seller.groups.remove(seller_group)
        
        # Option 3: Deactivate the user instead of deleting
        # seller.is_active = False
        # seller.save()
        
        return Response({'message': 'Seller removed successfully.'}, status=status.HTTP_204_NO_CONTENT)

# view controls admin login
@api_view(['POST'])
def admin_login(request):
    username = request.data.get('username')
    password = request.data.get('password')

    if not username or not password:
        return Response({'error': 'Please provide both username and password.'}, status=status.HTTP_400_BAD_REQUEST)

    user = authenticate(username=username, password=password)

    if user is None:
        return Response({'error': 'Invalid credentials.'}, status=status.HTTP_401_UNAUTHORIZED)

    if not user.is_active:
        return Response({'error': 'User account is inactive.'}, status=status.HTTP_403_FORBIDDEN)

    if not (user.is_superuser or user.groups.filter(name='Admin').exists()):
        return Response({'error': 'User is not an admin.'}, status=status.HTTP_403_FORBIDDEN)

    refresh = RefreshToken.for_user(user)

    return Response({
        'access': str(refresh.access_token),
        'refresh': str(refresh),
        'username': user.username,
        'email': user.email,
        'is_superuser': user.is_superuser
    })    

# view for login
class LoginView(APIView):
    def post(self, request):
        username = request.data.get("username")
        password = request.data.get("password")

        if not username or not password:
            return Response({"error": "Username and password are required"}, status=status.HTTP_400_BAD_REQUEST)

        user = authenticate(request, username=username, password=password)

        if user is None:
            return Response({"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)

        if not user.groups.filter(name='Seller').exists():
            return Response({"error": "User is not a seller"}, status=status.HTTP_403_FORBIDDEN)

        refresh = RefreshToken.for_user(user)

        return Response({
            "access": str(refresh.access_token),
            "refresh": str(refresh),
            "username": user.username,
        }, status=status.HTTP_200_OK)

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
            token = body.get('access')

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
        print("Received data:", request.data)  # Print the raw input data
        
        serializer = RegisterSerializer(data=request.data)
        
        if serializer.is_valid():
            print("Serializer is valid. Validated data:", serializer.validated_data)  # Print validated data
            
            user = serializer.save()

            try:
                seller_group = Group.objects.get(name='Seller')
                user.groups.add(seller_group)
            except Group.DoesNotExist:
                print("Seller group does not exist.")  # Print error info
                return Response(
                    {"error": "Seller group does not exist. Please create it in the admin panel."},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )

            print("User registered successfully:", user.username)  
            return Response({"message": "User registered successfully as Seller"}, status=status.HTTP_201_CREATED)

        print("Serializer errors:", serializer.errors) 
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


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
    
# view to get all transactions for sale history
@api_view(['GET'])
def sale_transactions(request):
    transactions = FarmSaleTransaction.objects.select_related('farm').all()
    serializer = FarmSaleTransactionSerializer(transactions, many=True)
    return Response(serializer.data)

# view to get all transactions for sale history
class SaleTransactionViewSet(viewsets.ModelViewSet):
    queryset = FarmSaleTransaction.objects.all() 
    serializer_class = FarmSaleTransactionSerializer
    permission_classes = [IsAuthenticated]  

    def get_queryset(self):
        return FarmSaleTransaction.objects.filter(farm__user=self.request.user)

# get the farms lists for sale by admin & sellers
@api_view(['GET'])
def get_sale_farms(request):
    farms = FarmSale.objects.all()
    serializer = FarmSaleSerializer(farms, many=True)
    return Response(serializer.data)

# get only the validated farms by buyers & renters
@api_view(['GET'])
def get_validated_sale_farms(request):
    farms = FarmSale.objects.filter(is_validated=True, is_rejected=False)
    serializer = FarmSaleSerializer(farms, many=True)
    return Response(serializer.data)


@api_view(['GET'])
def get_rent_farms(request):
    queryset = FarmRent.objects.all()
    location = request.GET.get("location")
    if location:
        queryset = queryset.filter(location__icontains=location)
    price = request.GET.get("price")
    if price:
        try:
            queryset = queryset.filter(price__lte=price)
        except ValueError:
            pass 
    size = request.GET.get("size")
    if size:
        queryset = queryset.filter(size__icontains=size)
    serializer = FarmRentSerializer(queryset, many=True)
    return Response(serializer.data)

# get the validated farms for rent
@api_view(['GET'])
def get_validated_rent_farms(request):
    queryset = FarmRent.objects.filter(is_validated=True, is_rejected=False)
    location = request.GET.get("location")
    if location:
        queryset = queryset.filter(location__icontains=location)
    price = request.GET.get("price")
    if price:
        try:
            queryset = queryset.filter(price__lte=price)
        except ValueError:
            pass 
    size = request.GET.get("size")
    if size:
        queryset = queryset.filter(size__icontains=size)
    serializer = FarmRentSerializer(queryset, many=True)
    return Response(serializer.data)

# view to provide endpoints such as edit, update and delete 
class FarmSaleDetailAPIView(generics.RetrieveUpdateAPIView):
    queryset = FarmSale.objects.all()
    serializer_class = FarmSaleSerializer

class FarmRentDetailAPIView(generics.RetrieveUpdateAPIView):
    queryset = FarmRent.objects.all()
    serializer_class = FarmRentSerializer

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
        if not request.user.is_authenticated:
            return Response({"error": "Authentication required"}, status=401)

        farm_type = request.data.get("farmType")
        images = request.FILES.getlist('images')

        if not (4 <= len(images) <= 10):
            return Response({"error": "Upload between 4 and 10 images."}, status=400)

        if farm_type == "Sale":
            serializer = FarmSaleSerializer(data=request.data)
        elif farm_type == "Rent":
            serializer = FarmRentSerializer(data=request.data)
        else:
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

    def patch(self, request, farm_type, farm_id):

        data = request.data

        if farm_type == "rent":
            transaction = FarmRentTransaction.objects.filter(farm_id=farm_id).first()
            serializer_class = FarmRentTransactionSerializer
        elif farm_type == "sale":
            transaction = FarmSaleTransaction.objects.filter(farm_id=farm_id).first()
            serializer_class = FarmSaleTransactionSerializer
        else:
            return Response({"error": "Invalid farm type"}, status=400)

        if not transaction:
            return Response({"error": "Transaction not found for this farm"}, status=404)

        transaction.is_validated = data.get("is_validated", transaction.is_validated)
        transaction.is_rejected = data.get("is_rejected", transaction.is_rejected)
        transaction.admin_feedback = data.get("admin_feedback", transaction.admin_feedback)
        transaction.save()

        serializer = serializer_class(transaction)
        return Response(serializer.data, status=200)

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
    
def download_contract(request, farm_id):
    """Download contract PDF"""
    try:
        farm = get_object_or_404(FarmRent, id=id)

        def generate_contract_pdf(farm):
            return f"PDF content for farm {farm.farm_number}".encode('utf-8')

        pdf_content = generate_contract_pdf(farm)

        response = HttpResponse(pdf_content, content_type='application/pdf')
        response['Content-Disposition'] = (
            f'attachment; filename="Mkataba_wa_Kukodisha_Shamba_{farm.farm_number}.pdf"'
        )

        return response

    except Exception as e:
        print("Error occurred while generating PDF:")
        traceback.print_exc()

        return JsonResponse(
            {"error": f"Hitilafu katika kutengeneza PDF: {str(e)}"},
            status=500
        )

# controls deactivation after successful transaction id generation
@api_view(['PATCH'])
def update_farm_sold_status(request, pk):

    try:
        farm = FarmSale.objects.get(pk=pk)
    except FarmSale.DoesNotExist:
        return Response(status=status.HTTP_404_NOT_FOUND)

    if 'is_sold' not in request.data or len(request.data) > 1:
        return Response(
            {"detail": "Only the 'is_sold' field can be updated via this endpoint."},
            status=status.HTTP_400_BAD_REQUEST
        )

    serializer = FarmSaleSerializer(farm, data=request.data, partial=True)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



@api_view(['PATCH'])
def update_farm_rented_status(request, pk):
    try:
        farm = FarmRent.objects.get(pk=pk)
    except FarmRent.DoesNotExist:
        return Response(status=status.HTTP_404_NOT_FOUND)

    # This ensures only 'is_rented' can be updated via this endpoint
    if 'is_rented' not in request.data or len(request.data) > 1:
        return Response(
            {"detail": "Only the 'is_rented' field can be updated via this endpoint."},
            status=status.HTTP_400_BAD_REQUEST
        )

    serializer = FarmRentSerializer(farm, data=request.data, partial=True)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


