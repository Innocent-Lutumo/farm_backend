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
from django.http import JsonResponse, HttpResponse, FileResponse
from django.utils.encoding import force_str, force_bytes
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.auth.tokens import default_token_generator
from django.shortcuts import get_object_or_404
from django.template.loader import render_to_string
from django.core.mail import send_mail
from django.db.models import Q
from django.conf import settings
from rest_framework.decorators import api_view, action
from rest_framework import viewsets
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework import generics
from .utils import generate_rental_agreement_pdf 

from .utils import verify_google_token
from .serializers import (
    RegisterSerializer, 
    CustomTokenObtainPairSerializer, 
    FarmSaleSerializer, 
    FarmRentSerializer, 
    FarmRentTransactionSerializer, 
    FarmSaleTransactionSerializer,
    RentalAgreementSerializer
)

from .models import (
    FarmSale, FarmRent, 
    FarmImage, 
    FarmRentTransaction, FarmSaleTransaction,
    RentalAgreement,
)

from django.core.files.base import ContentFile
from .PDF_generator import RentalAgreementPDFGenerator
import json
import traceback
from google.oauth2 import id_token
from google.auth.transport.requests import Request
import io
from reportlab.pdfgen import canvas
import logging

# Configure logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet
import os

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

    seller_group = Group.objects.get(name='Seller')
    sellers = User.objects.filter(groups=seller_group)
    
    serializer = RegisterSerializer(sellers, many=True)
    return Response(serializer.data)

# unprotected version for get sellers
User = get_user_model()

@api_view(['GET'])
def get_sellers_unprotected(request):
    seller_group = Group.objects.get(name='Seller')
    sellers = User.objects.filter(groups=seller_group)
    
    serializer = RegisterSerializer(sellers, many=True)
    return Response(serializer.data)

@api_view(['GET', 'PUT', 'DELETE'])
@permission_classes([IsAuthenticated])
def seller_detail(request, pk):
    user = request.user
    if not (user.is_superuser or user.groups.filter(name='Admin').exists()):
        return Response({'error': 'User is not an admin.'}, status=status.HTTP_403_FORBIDDEN)
    
    try:
        seller = User.objects.get(pk=pk)
        if not seller.groups.filter(name='Seller').exists():
            return Response({'error': 'User is not a seller.'}, status=status.HTTP_400_BAD_REQUEST)
    except User.DoesNotExist:
        return Response({'error': 'Seller not found.'}, status=status.HTTP_404_NOT_FOUND)
    
    # GET request to retrieve seller details
    if request.method == 'GET':
        serializer = RegisterSerializer(seller)
        return Response(serializer.data)
    
    # DELETE request to remove a seller
    elif request.method == 'DELETE':
        try:
            seller_group = Group.objects.get(name='Seller')
            seller.groups.remove(seller_group)
            
            return Response({'message': 'Seller removed successfully.'}, status=status.HTTP_200_OK)
            
        except Group.DoesNotExist:
            return Response({'error': 'Seller group not found.'}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
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
                    'last_name': user_info.get('family_name', ''),
                    'email': user_info['email']  
                }
            )
            
            # FIX: Changed from 'refresh = refresh.for_user(user)' to 'refresh = RefreshToken.for_user(user)'
            refresh = RefreshToken.for_user(user)
            
            return JsonResponse({
                "message": "Google login successful",
                "user_info": user_info,
                "access": str(refresh.access_token),  
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
        print("Received data:", request.data)  
        
        serializer = RegisterSerializer(data=request.data)
        
        if serializer.is_valid():
            print("Serializer is valid. Validated data:", serializer.validated_data)  
            
            user = serializer.save()

            try:
                seller_group = Group.objects.get(name='Seller')
                user.groups.add(seller_group)
            except Group.DoesNotExist:
                print("Seller group does not exist.") 
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

    # The serializer will now include the username based on your serializer configuration
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
            print(farm)

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
    permission_classes = [IsAuthenticated]

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
            return Response({"error": "Farm not found"}, status=status.HTTP_404_NOT_FOUND)
        serializer = serializer_class(farm, context={'request': request}) # Add context for full image URLs
        return Response(serializer.data)


    def put(self, request, farm_type, farm_id):
        farm, serializer_class = self.get_farm(farm_id, farm_type)
        if not farm:
            return Response({"error": "Farm not found"}, status=status.HTTP_404_NOT_FOUND)

        # request.data intelligently handles both form data and files for multipart requests.
        # No need to explicitly separate request.FILES unless you have a very specific reason.
        # Just pass request.data directly to the serializer.
        serializer = serializer_class(
            farm,
            data=request.data,  # Pass request.data directly
            partial=True,       # Allow partial updates
            context={'request': request}
        )

        if serializer.is_valid():
            instance = serializer.save()

            # Handle new image uploads (if 'images' is a ManyToMany field or similar)
            # If `images` is a separate model (FarmImage) as indicated by your `FarmImage.objects.create` line,
            # you need to be careful. The current approach assumes:
            # 1. Your FarmSale/FarmRent models don't have an 'images' field directly.
            # 2. FarmImage has a ForeignKey to FarmSale/FarmRent (which is 'farm').
            # 3. You want to ADD new images, not replace existing ones unless explicitly handled.
            # If you want to replace all images, you'd delete existing ones first.
            # If the 'images' field in your serializer for FarmSale/FarmRent is a `ManyRelatedField`
            # or `PrimaryKeyRelatedField` pointing to existing FarmImage IDs, then DRF handles it.
            # If you're using this manual creation, it implies new images are always *added*.
            new_images_uploaded = request.FILES.getlist('images', [])
            if new_images_uploaded:
                # OPTIONAL: If you want to clear existing images when new ones are uploaded:
                # instance.images.all().delete() # if 'images' is a related manager on the farm model
                # or
                # FarmImage.objects.filter(farm=instance).delete() # if FarmImage relates to farm

                for img_file in new_images_uploaded:
                    FarmImage.objects.create(
                        farm=instance,
                        image=img_file
                    )

            # DRF's serializer with partial=True should handle `passport` and `ownership_certificate`
            # automatically if they are `FileField`s in the model and serializer,
            # as long as the new file is sent in the FormData.
            # If a field (like passport/ownership_certificate) is not in `request.data`,
            # `partial=True` means the existing value is kept.

            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def delete(self, request, farm_type, farm_id):
        farm, _ = self.get_farm(farm_id, farm_type) 
        if not farm:
            return Response({"error": "Farm not found"}, status=status.HTTP_404_NOT_FOUND)
            
        farm.delete()
        return Response({"message": "Farm deleted successfully"}, status=status.HTTP_204_NO_CONTENT)
    
    def patch(self, request, farm_type, farm_id):
        data = request.data
        if farm_type == "rent":
            transaction = FarmRentTransaction.objects.filter(farm_id=farm_id).first()
            serializer_class = FarmRentTransactionSerializer
        elif farm_type == "sale":
            transaction = FarmSaleTransaction.objects.filter(farm_id=farm_id).first()
            serializer_class = FarmSaleTransactionSerializer
        else:
            return Response({"error": "Invalid farm type"}, status=status.HTTP_400_BAD_REQUEST)
        
        if not transaction:
            return Response({"error": "Transaction not found for this farm"}, status=status.HTTP_404_NOT_FOUND)
        
        transaction.is_validated = data.get("is_validated", transaction.is_validated)
        transaction.is_rejected = data.get("is_rejected", transaction.is_rejected)
        transaction.admin_feedback = data.get("admin_feedback", transaction.admin_feedback)
        transaction.save()
        
        serializer = serializer_class(transaction)
        return Response(serializer.data, status=status.HTTP_200_OK)

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
    location = request.data.get('location')
    size = request.data.get('size')
    price = request.data.get('price')

    if not email or not transaction_id:
        return Response({'error': 'Missing renter_email or transaction_id'}, status=400)

    try:
        send_mail(
            'Your Transaction ID from Farm Finder',
            f'Thank you for your rental request for the farm rented for {price}TZS located at {location} and the size {size}. Your transaction ID is: {transaction_id} keep the id  safe for the history tracking to know the seller feedack and to access the phone number and email to directly communicate with the seller',
            settings.EMAIL_HOST_USER,
            [email]
        )
        return Response({'message': 'Email sent successfully.'}, status=200)
    except Exception as e:
        return Response({'error': f'Failed to send email: {str(e)}'}, status=500)

# controls deactivation after successful transaction id generation for sale
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

# controls deactivation after successful transaction id generation for rent
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

class ValidatedFarmRentView(generics.RetrieveAPIView):
    queryset = FarmRent.objects.filter(is_validated=True)
    serializer_class = FarmRentSerializer

    def get_object(self):
        return self.queryset.order_by('-created_at').first()

    def get(self, request, *args, **kwargs):
        instance = self.get_object()
        if not instance:
            return Response({"detail": "No validated farm rental agreement found."},
                            status=status.HTTP_404_NOT_FOUND)
        serializer = self.get_serializer(instance)
        return Response(serializer.data)
    
# view for creating a rental agreement
class CreateRentalAgreementView(generics.CreateAPIView):
    queryset = RentalAgreement.objects.all()
    serializer_class = RentalAgreementSerializer
    
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        # Calculate financial terms
        monthly_rent = serializer.validated_data['monthly_rent']
        serializer.validated_data['deposit_amount'] = monthly_rent * 2
        serializer.validated_data['initial_payment'] = monthly_rent
        
        # Create the agreement
        self.perform_create(serializer)
        
        # Generate PDF after creation
        agreement = serializer.instance
        try:
            pdf_path = generate_rental_agreement_pdf(agreement)
            agreement.pdf_document = os.path.relpath(pdf_path, settings.MEDIA_ROOT)
            agreement.save()
        except Exception as e:
            # Log the error but don't fail the request
            print(f"Error generating PDF: {str(e)}")
        
        headers = self.get_success_headers(serializer.data)
        
        return Response({
            'success': True,
            'agreement_id': agreement.agreement_id, 
            'message': 'Rental agreement created successfully'
        }, status=status.HTTP_201_CREATED, headers=headers)

class DownloadRentalAgreementView(APIView):
    def get(self, request, agreement_id):
        try:
            agreement = get_object_or_404(RentalAgreement, agreement_id=agreement_id)
            
            if not agreement.pdf_document:
                # Try to generate PDF if it doesn't exist
                pdf_path = generate_rental_agreement_pdf(agreement)
                agreement.pdf_document = os.path.relpath(pdf_path, settings.MEDIA_ROOT)
                agreement.save()
            
            file_path = os.path.join(settings.MEDIA_ROOT, str(agreement.pdf_document))
            
            if os.path.exists(file_path):
                response = FileResponse(
                    open(file_path, 'rb'), 
                    content_type='application/pdf'
                )
                response['Content-Disposition'] = (
                    f'attachment; filename="Mkataba_wa_Kukodisha_Shamba_{agreement_id}.pdf"'
                )
                return response
            
            return Response(
                {'error': 'PDF file not found on server and could not be generated'},
                status=status.HTTP_404_NOT_FOUND
            )
            
        except Exception as e:
            return Response(
                {'error': f'Error processing PDF: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
