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
from django.http import JsonResponse, HttpResponse
from django.core.mail import send_mail
from django.utils import timezone
from django.conf import settings
from rest_framework.decorators import api_view
from rest_framework import viewsets
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework import generics
from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.views import View
import json
from io import BytesIO
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from datetime import datetime
from reportlab.lib.styles import getSampleStyleSheet
import logging

from .utils import verify_google_token
from .serializers import (
    RegisterSerializer, 
    CustomTokenObtainPairSerializer, 
    FarmSaleSerializer, 
    FarmRentSerializer, 
    FarmRentTransactionSerializer, 
    FarmSaleTransactionSerializer,
)

from .models import (
    FarmSale, FarmRent, 
    FarmImage, 
    FarmRentTransaction, FarmSaleTransaction,
    RentalAgreement, 
)

from google.oauth2 import id_token
from google.auth.transport.requests import Request

# Configure logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

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
        serializer = serializer_class(farm, context={'request': request})
        return Response(serializer.data)

    def put(self, request, farm_type, farm_id):
        farm, serializer_class = self.get_farm(farm_id, farm_type)
        if not farm:
            return Response({"error": "Farm not found"}, status=status.HTTP_404_NOT_FOUND)

        serializer = serializer_class(
            farm,
            data=request.data,
            partial=True,
            context={'request': request}
        )

        if serializer.is_valid():
            instance = serializer.save()
            new_images_uploaded = request.FILES.getlist('images', [])
            
            if new_images_uploaded:
                # Clear existing images if needed (optional)
                # instance.images.all().delete()
                
                for img_file in new_images_uploaded:
                    if farm_type == "sale":
                        FarmImage.objects.create(
                            farm_sale=instance,
                            image=img_file,
                            uploaded_at=timezone.now()
                        )
                    elif farm_type == "rent":
                        FarmImage.objects.create(
                            farm_rent=instance,
                            image=img_file,
                            uploaded_at=timezone.now()
                        )

            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def delete(self, request, farm_type, farm_id):
        farm, _ = self.get_farm(farm_id, farm_type) 
        if not farm:
            return Response({"error": "Farm not found"}, status=status.HTTP_404_NOT_FOUND)
            
        # Delete associated images first
        if farm_type == "sale":
            FarmImage.objects.filter(farm_sale=farm).delete()
        elif farm_type == "rent":
            FarmImage.objects.filter(farm_rent=farm).delete()
            
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

# view to create a rental agreement 

logger = logging.getLogger(__name__)

class RentalAgreementPDFGenerator:
    def __init__(self, agreement_data):
        self.data = agreement_data
        self.buffer = BytesIO()
        self.doc = SimpleDocTemplate(
            self.buffer,
            pagesize=A4,
            rightMargin=2*cm,
            leftMargin=2*cm,
            topMargin=2*cm,
            bottomMargin=2*cm
        )
        self.styles = getSampleStyleSheet()
        self.story = []
        
        # Custom styles
        self.title_style = ParagraphStyle(
            'CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=16,
            spaceAfter=12,
            alignment=TA_CENTER,
            textColor=colors.darkgreen
        )
        
        self.heading_style = ParagraphStyle(
            'CustomHeading',
            parent=self.styles['Heading2'],
            fontSize=12,
            spaceAfter=8,
            textColor=colors.darkblue
        )
        
        self.normal_style = ParagraphStyle(
            'CustomNormal',
            parent=self.styles['Normal'],
            fontSize=10,
            spaceAfter=6
        )

    def add_header(self):
        """Add document header"""
        header_data = [
            [Paragraph("JAMHURI YA MUUNGANO WA TANZANIA", self.title_style)],
            [Paragraph("MKATABA WA KUKODISHA SHAMBA", self.title_style)],
            [Paragraph("(Farm Rental Agreement)", self.normal_style)],
            [Paragraph(f"Namba ya Shamba: {self.data.get('farm_number', 'N/A')}", self.normal_style)],
            [Paragraph(f"Tarehe: {self.format_date(self.data.get('agreement_date'))}", self.normal_style)]
        ]
        
        header_table = Table(header_data, colWidths=[17*cm])
        header_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        
        self.story.append(header_table)
        self.story.append(Spacer(1, 0.5*cm))

    def add_parties_section(self):
        """Add parties information"""
        self.story.append(Paragraph("WAHUSIKA WA MKATABA", self.heading_style))
        
        # Parties table
        parties_data = [
            [
                Paragraph("<b>MKODISHAJI (LANDLORD)</b>", self.normal_style),
                Paragraph("<b>MKODISHWA (TENANT)</b>", self.normal_style)
            ],
            [
                Paragraph(f"<b>Jina:</b> {self.data.get('landlord_name', 'N/A')}", self.normal_style),
                Paragraph(f"<b>Jina:</b> {self.data.get('full_name', 'N/A')}", self.normal_style)
            ],
            [
                Paragraph(f"<b>Simu:</b> {self.data.get('landlord_phone', 'N/A')}", self.normal_style),
                Paragraph(f"<b>Simu:</b> {self.data.get('renter_phone', 'N/A')}", self.normal_style)
            ],
            [
                Paragraph(f"<b>Barua Pepe:</b> {self.data.get('landlord_email', 'N/A')}", self.normal_style),
                Paragraph(f"<b>Barua Pepe:</b> {self.data.get('renter_email', 'N/A')}", self.normal_style)
            ],
            [
                Paragraph(f"<b>Makazi:</b> {self.data.get('landlord_residence', 'N/A')}", self.normal_style),
                Paragraph(f"<b>Makazi:</b> {self.data.get('residence', 'N/A')}", self.normal_style)
            ]
        ]
        
        parties_table = Table(parties_data, colWidths=[8.5*cm, 8.5*cm])
        parties_table.setStyle(TableStyle([
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('LEFTPADDING', (0, 0), (-1, -1), 6),
            ('RIGHTPADDING', (0, 0), (-1, -1), 6),
            ('GRID', (0, 0), (-1, -1), 1, colors.lightgrey),
        ]))
        
        self.story.append(parties_table)
        self.story.append(Spacer(1, 0.5*cm))

    def add_property_details(self):
        """Add property details section"""
        self.story.append(Paragraph("MAELEZO YA SHAMBA", self.heading_style))
        
        property_data = [
            [
                Paragraph(f"<b>Eneo:</b> {self.data.get('location', 'N/A')}", self.normal_style),
                Paragraph(f"<b>Ukubwa:</b> {self.data.get('size', 'N/A')} Ekari", self.normal_style)
            ],
            [
                Paragraph(f"<b>Udongo:</b> {self.data.get('quality', 'N/A')}", self.normal_style),
                Paragraph(f"<b>Aina:</b> {self.data.get('farm_type', 'N/A')}", self.normal_style)
            ]
        ]
        
        if self.data.get('description'):
            property_data.append([
                Paragraph(f"<b>Maelezo Ziada:</b> {self.data.get('description')}", self.normal_style),
                ""
            ])
        
        property_table = Table(property_data, colWidths=[8.5*cm, 8.5*cm])
        property_table.setStyle(TableStyle([
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('LEFTPADDING', (0, 0), (-1, -1), 6),
            ('RIGHTPADDING', (0, 0), (-1, -1), 6),
            ('GRID', (0, 0), (-1, -1), 1, colors.lightgrey),
        ]))
        
        self.story.append(property_table)
        self.story.append(Spacer(1, 0.5*cm))

    def add_financial_terms(self):
        """Add financial terms section"""
        self.story.append(Paragraph("MASHARTI YA KIFEDHA", self.heading_style))
        
        price = float(self.data.get('price', 0))
        deposit = price * 2
        advance = price
        
        financial_data = [
            [
                Paragraph(f"<b>Kodi ya Mwezi:</b><br/>TZS {price:,.0f}", self.normal_style),
                Paragraph(f"<b>Dhamana:</b><br/>TZS {deposit:,.0f}", self.normal_style),
                Paragraph(f"<b>Malipo ya Awali:</b><br/>TZS {advance:,.0f}", self.normal_style)
            ]
        ]
        
        financial_table = Table(financial_data, colWidths=[5.67*cm, 5.67*cm, 5.67*cm])
        financial_table.setStyle(TableStyle([
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('LEFTPADDING', (0, 0), (-1, -1), 6),
            ('RIGHTPADDING', (0, 0), (-1, -1), 6),
            ('GRID', (0, 0), (-1, -1), 1, colors.lightgrey),
            ('BACKGROUND', (0, 0), (-1, -1), colors.lightblue),
        ]))
        
        self.story.append(financial_table)
        self.story.append(Spacer(1, 0.5*cm))

    def add_terms_and_conditions(self):
        """Add terms and conditions"""
        self.story.append(Paragraph("MASHARTI NA HALI ZA MKATABA", self.heading_style))
        
        duration = self.data.get('duration_months', 12)
        start_date = self.format_date(self.data.get('agreement_date'))
        
        terms = [
            f"1. Mkataba huu ni wa miezi {duration} kuanzia {start_date}.",
            "2. Kodi hulipwa mwanzoni mwa kila mwezi. Faini ya 5% kwa kuchelewa zaidi ya siku 7.",
            "3. Mkodishwa atatunza shamba vizuri na kuitumia kwa kilimo pekee.",
            "4. Mkodishaji atahakikisha haki ya matumizi na kutoa msaada unapohitajika.",
            "5. Mkataba unaweza kufutwa kwa kukiuka masharti haya.",
            "6. Migogoro itasululiwa kwa mazungumzo au mahakama za Tanzania.",
            "7. Dhamana itarudishwa mwishoni mwa mkataba ikiwa hakuna uharibifu.",
            "8. Mkodishwa hawezi kuuza au kukodisha shamba kwa mtu mwingine bila idhini.",
            "9. Kodi inaweza kuongezwa kwa 10% kila mwaka baada ya miaka miwili.",
            "10. Mkataba huu unaongozwa na sheria za Tanzania."
        ]
        
        for term in terms:
            self.story.append(Paragraph(term, self.normal_style))
        
        self.story.append(Spacer(1, 0.5*cm))

    def add_signatures(self):
        """Add signature section"""
        self.story.append(Paragraph("SAHIHI NA MASHAHIDI", self.heading_style))
        
        # Signature table
        signature_data = [
            [
                Paragraph("<b>MKODISHAJI:</b>", self.normal_style),
                Paragraph("<b>MKODISHWA:</b>", self.normal_style)
            ],
            [
                Paragraph("Sahihi: _________________________", self.normal_style),
                Paragraph("Sahihi: _________________________", self.normal_style)
            ],
            [
                Paragraph(f"Tarehe: {self.format_date(datetime.now())}", self.normal_style),
                Paragraph("Tarehe: __________________", self.normal_style)
            ],
            ["", ""],  # Space
            [
                Paragraph("<b>MDHAMINI 1:</b>", self.normal_style),
                Paragraph("<b>MDHAMINI 2:</b>", self.normal_style)
            ],
            [
                Paragraph("Jina: _________________________", self.normal_style),
                Paragraph("Jina: _________________________", self.normal_style)
            ],
            [
                Paragraph("Sahihi: _________________________", self.normal_style),
                Paragraph("Sahihi: _________________________", self.normal_style)
            ]
        ]
        
        signature_table = Table(signature_data, colWidths=[8.5*cm, 8.5*cm])
        signature_table.setStyle(TableStyle([
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('LEFTPADDING', (0, 0), (-1, -1), 6),
            ('RIGHTPADDING', (0, 0), (-1, -1), 6),
            ('LINEBELOW', (0, 1), (-1, 1), 1, colors.black),
            ('LINEBELOW', (0, 5), (-1, 5), 1, colors.black),
            ('LINEBELOW', (0, 6), (-1, 6), 1, colors.black),
        ]))
        
        self.story.append(signature_table)

    def add_footer(self):
        """Add footer"""
        self.story.append(Spacer(1, 1*cm))
        footer_text = (
            "Mkataba huu umejumuishwa chini ya sheria za Tanzania. "
            "Kwa maswali, wasiliana na msimamizi wa mfumo."
        )
        self.story.append(Paragraph(footer_text, self.normal_style))

    def format_date(self, date_input):
        """Format date to DD/MM/YYYY"""
        if not date_input:
            return datetime.now().strftime("%d/%m/%Y")
        
        if isinstance(date_input, str):
            try:
                date_obj = datetime.fromisoformat(date_input.replace('Z', '+00:00'))
                return date_obj.strftime("%d/%m/%Y")
            except:
                return date_input
        elif isinstance(date_input, datetime):
            return date_input.strftime("%d/%m/%Y")
        
        return str(date_input)

    def generate_pdf(self):
        """Generate the complete PDF"""
        try:
            self.add_header()
            self.add_parties_section()
            self.add_property_details()
            self.add_financial_terms()
            self.add_terms_and_conditions()
            self.add_signatures()
            self.add_footer()
            
            self.doc.build(self.story)
            self.buffer.seek(0)
            return self.buffer
        except Exception as e:
            logger.error(f"Error generating PDF: {str(e)}")
            raise

# view to create a rental agreement
@method_decorator(csrf_exempt, name='dispatch')
class CreateRentalAgreementView(View):
    def post(self, request):
        try:
            data = json.loads(request.body)
            logger.info(f"Creating rental agreement with data: {data}")
            
            # Validate required fields
            required_fields = [
                'location', 'size', 'quality', 'price', 'full_name',
                'renter_phone', 'renter_email', 'residence'
            ]
            
            missing_fields = [field for field in required_fields if not data.get(field)]
            if missing_fields:
                return JsonResponse({
                    'success': False,
                    'error': f'Missing required fields: {", ".join(missing_fields)}'
                }, status=400)
            
            # Create rental agreement record
            agreement = RentalAgreement.objects.create(
                farm_id=data.get('farm_id'),
                transaction_id=data.get('transaction_id'),
                farm_number=data.get('farm_number'),
                location=data.get('location'),
                size=float(data.get('size')),
                quality=data.get('quality'),
                farm_type=data.get('farm_type', ''),
                description=data.get('description', ''),
                price=float(data.get('price')),
                full_name=data.get('full_name'),
                renter_phone=data.get('renter_phone'),
                renter_email=data.get('renter_email'),
                residence=data.get('residence'),
                landlord_name=data.get('landlord_name', ''),
                landlord_phone=data.get('landlord_phone', ''),
                landlord_email=data.get('landlord_email', ''),
                landlord_residence=data.get('landlord_residence', ''),
                landlord_passport=data.get('landlord_passport', ''),
                # agreement_date=data.get('agreement_date', datetime.now()),
                duration_months=int(data.get('duration_months', 12)),
                status='active'
            )
            
            logger.info(f"Agreement created successfully with ID: {agreement.id}")
            
            return JsonResponse({
                'success': True,
                'message': 'Rental agreement created successfully',
                'agreement_id': agreement.id
            })
            
        except json.JSONDecodeError:
            return JsonResponse({
                'success': False,
                'error': 'Invalid JSON data'
            }, status=400)
        except Exception as e:
            logger.error(f"Error creating rental agreement: {str(e)}")
            return JsonResponse({
                'success': False,
                'error': str(e)
            }, status=500)

# view to download the rental agreement as a PDF        
@method_decorator(csrf_exempt, name='dispatch')  
class DownloadRentalAgreementView(View):
    def get(self, request, pk):  
        try:
            logger.info(f"Downloading PDF for agreement ID: {pk}")
            
            # Get agreement from database
            try:
                agreement = RentalAgreement.objects.get(id=pk)  
            except RentalAgreement.DoesNotExist:
                return JsonResponse({
                    'error': 'Agreement not found'
                }, status=404)
            
            # Rest of your code remains the same...
            agreement_data = {
                'farm_number': agreement.farm_number,
                'location': agreement.location,
                'size': agreement.size,
                'quality': agreement.quality,
                'farm_type': agreement.farm_type,
                'description': agreement.description,
                'price': agreement.price,
                'full_name': agreement.full_name,
                'renter_phone': agreement.renter_phone,
                'renter_email': agreement.renter_email,
                'residence': agreement.residence,
                'landlord_name': agreement.landlord_name,
                'landlord_phone': agreement.landlord_phone,
                'landlord_email': agreement.landlord_email,
                'landlord_residence': agreement.landlord_residence,
                'landlord_passport': agreement.landlord_passport,
                # 'agreement_date': agreement.agreement_date,
                'duration_months': agreement.duration_months,
            }
            
            pdf_generator = RentalAgreementPDFGenerator(agreement_data)
            pdf_buffer = pdf_generator.generate_pdf()
            
            response = HttpResponse(
                pdf_buffer.getvalue(),
                content_type='application/pdf'
            )
            response['Content-Disposition'] = f'attachment; filename="Mkataba_wa_Kukodisha_Shamba_{pk}.pdf"'
            response['Content-Length'] = len(pdf_buffer.getvalue())
            
            logger.info(f"PDF generated successfully. Size: {len(pdf_buffer.getvalue())} bytes")
            return response
            
        except Exception as e:
            logger.error(f"Error downloading PDF: {str(e)}")
            return JsonResponse({
                'error': f'Error generating PDF: {str(e)}'
            }, status=500)