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
import io
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet

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
        
        # Check if user owns this farm (optional security check)
        # if hasattr(farm, 'email') and farm.email != request.user.email:
        #     return Response({"error": "Permission denied"}, status=status.HTTP_403_FORBIDDEN)
            
        # serializer = serializer_class(farm)
        # return Response(serializer.data)
    
    def put(self, request, farm_type, farm_id):
        farm, serializer_class = self.get_farm(farm_id, farm_type)
        if not farm:
            return Response({"error": "Farm not found"}, status=status.HTTP_404_NOT_FOUND)
        
        # Check if user owns this farm
        # if hasattr(farm, 'email') and farm.email != request.user.email:
        #     return Response({"error": "Permission denied"}, status=status.HTTP_403_FORBIDDEN)
        
        serializer = serializer_class(farm, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def delete(self, request, farm_type, farm_id):
        farm, _ = self.get_farm(farm_id, farm_type) 
        if not farm:
            return Response({"error": "Farm not found"}, status=status.HTTP_404_NOT_FOUND)
        
        # Check if user owns this farm
        # if hasattr(farm, 'email') and farm.email != request.user.email:
        #     return Response({"error": "Permission denied"}, status=status.HTTP_403_FORBIDDEN)
            
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
        # This will fetch the most recently validated farm rent contract
        # You might want to adjust this logic based on how you determine
        # which "validated" contract to display.
        # For example, if you pass an ID from the frontend, it would be:
        # return get_object_or_404(FarmRent, id=self.kwargs['pk'], is_validated=True)
        return self.queryset.order_by('-created_at').first()

    def get(self, request, *args, **kwargs):
        instance = self.get_object()
        if not instance:
            return Response({"detail": "No validated farm rental agreement found."},
                            status=status.HTTP_404_NOT_FOUND)
        serializer = self.get_serializer(instance)
        return Response(serializer.data)


class DownloadContractPDFView(generics.RetrieveAPIView):
    queryset = FarmRent.objects.all()

    def get(self, request, *args, **kwargs):
        contract_id = self.kwargs.get('pk')
        farm_rent_contract = get_object_or_404(FarmRent, pk=contract_id)

        buffer = io.BytesIO()
        p = canvas.Canvas(buffer, pagesize=letter)
        styles = getSampleStyleSheet()

        # Add custom styles for better readability
        p.setFont("Helvetica-Bold", 18)
        p.drawCentredString(letter[0]/2.0, letter[1] - 50, "JAMHURI YA MUUNGANO WA TANZANIA")
        p.setFont("Helvetica-Bold", 24)
        p.setFillColorRGB(0.2, 0.6, 0.2) # Green color
        p.drawCentredString(letter[0]/2.0, letter[1] - 80, "MKATABA WA KUKODISHA SHAMBA")
        p.setFillColorRGB(0, 0, 0) # Back to black
        p.setFont("Helvetica", 10)
        p.drawCentredString(letter[0]/2.0, letter[1] - 100, "(Farm Rental Agreement)")

        # Contract Number and Date
        p.setFont("Helvetica-Bold", 12)
        p.drawString(inch, letter[1] - 140, f"Namba ya Mkataba: {farm_rent_contract.farm_number or f'MKS-{farm_rent_contract.id}'}")
        p.drawString(inch, letter[1] - 155, f"Tarehe: {farm_rent_contract.created_at.strftime('%d/%m/%Y')}")

        p.line(inch, letter[1] - 170, letter[0] - inch, letter[1] - 170) # Divider

        # Parties Section
        y_position = letter[1] - 200
        p.setFont("Helvetica-Bold", 14)
        p.drawString(inch, y_position, "WAHUSIKA WA MKATABA")

        y_position -= 20
        p.setFont("Helvetica-Bold", 12)
        p.drawString(inch, y_position, "MKODISHAJI (LANDLORD):")
        p.setFont("Helvetica", 10)
        p.drawString(inch + 0.2 * inch, y_position - 15, f"Jina: Jina la Mkodishaji (Placeholder from AdminSeller)") # This needs to come from AdminSeller
        p.drawString(inch + 0.2 * inch, y_position - 30, f"Simu: +255 7XX XXX XXX (Placeholder from AdminSeller)")
        p.drawString(inch + 0.2 * inch, y_position - 45, f"Barua pepe: mkodishaji@mfano.com (Placeholder from AdminSeller)")
        p.drawString(inch + 0.2 * inch, y_position - 60, f"Makazi: Makazi ya Mkodishaji (Placeholder from AdminSeller)")


        y_position -= 90
        p.setFont("Helvetica-Bold", 12)
        p.drawString(inch, y_position, "MKODISHWA (TENANT):")
        p.setFont("Helvetica", 10)
        p.drawString(inch + 0.2 * inch, y_position - 15, f"Jina: {farm_rent_contract.full_name}")
        p.drawString(inch + 0.2 * inch, y_position - 30, f"Simu: {farm_rent_contract.phone}")
        p.drawString(inch + 0.2 * inch, y_position - 45, f"Barua pepe: {farm_rent_contract.email or 'N/A'}")
        p.drawString(inch + 0.2 * inch, y_position - 60, f"Makazi: {farm_rent_contract.tenant_residence}")

        p.line(inch, y_position - 90, letter[0] - inch, y_position - 90) # Divider

        # Property Description
        y_position -= 120
        p.setFont("Helvetica-Bold", 14)
        p.drawString(inch, y_position, "MAELEZO YA SHAMBA")
        p.setFont("Helvetica", 10)
        y_position -= 20
        p.drawString(inch, y_position, f"Eneo: {farm_rent_contract.location}")
        y_position -= 15
        p.drawString(inch, y_position, f"Ukubwa: {farm_rent_contract.size} Ekari")
        y_position -= 15
        p.drawString(inch, y_position, f"Udongo: {farm_rent_contract.quality}")
        y_position -= 15
        p.drawString(inch, y_position, f"Aina: {farm_rent_contract.farm_type}")
        if farm_rent_contract.description:
            y_position -= 15
            p.drawString(inch, y_position, f"Maelezo Ziada: {farm_rent_contract.description}")

        p.line(inch, y_position - 30, letter[0] - inch, y_position - 30) # Divider

        # Financial Terms
        y_position -= 60
        p.setFont("Helvetica-Bold", 14)
        p.drawString(inch, y_position, "MASHARTI YA KIFEDHA")
        p.setFont("Helvetica", 10)
        y_position -= 20
        p.drawString(inch, y_position, f"Kodi ya Mwezi: TZS {farm_rent_contract.price:,.2f}")
        y_position -= 15
        p.drawString(inch, y_position, f"Dhamana: TZS {(farm_rent_contract.price * 2):,.2f}")
        y_position -= 15
        p.drawString(inch, y_position, f"Malipo ya Awali: TZS {farm_rent_contract.price:,.2f}")

        p.line(inch, y_position - 30, letter[0] - inch, y_position - 30) # Divider

        # General Terms and Conditions
        y_position -= 60
        p.setFont("Helvetica-Bold", 14)
        p.drawString(inch, y_position, "MASHARTI NA HALI ZA MKATABA")
        p.setFont("Helvetica", 10)
        y_position -= 20

        terms = [
            f"Mkataba huu ni wa miezi 12, kuanzia tarehe {farm_rent_contract.created_at.strftime('%d/%m/%Y')}.",
            "Kodi hulipwa mwanzoni mwa kila mwezi. Kutochelewa kulipa kunaweza kusababisha faini ya 5% ya kodi ya mwezi.",
            "Mkodishwa anatakiwa kutunza shamba katika hali nzuri na atatumia shamba kwa madhumuni ya kilimo pekee.",
            "Mkodisha atahakikisha haki ya matumizi ya amani na atatoa msaada wowote unaohitajika kwa mkodishwa.",
            "Matengenezo madogo madogo ya shamba ni jukumu la mkodishwa. Matengenezo makubwa ni jukumu la mkodishaji.",
            "Mkataba huu unaweza kusitishwa na upande wowote kwa kutoa notisi ya maandishi ya miezi miwili.",
            "Migogoro yoyote inayotokana na mkataba huu itatatuliwa kwa amani, na kama itashindikana, itapelekwa kwa Baraza la Usuluhishi au Mahakama za Tanzania."
        ]

        for term in terms:
            textobject = p.beginText(inch, y_position)
            textobject.textLine(term)
            p.drawText(textobject)
            y_position -= 15 # Adjust spacing for terms

        p.line(inch, y_position - 30, letter[0] - inch, y_position - 30) # Divider

        # Signatures and Witnesses
        y_position -= 60
        p.setFont("Helvetica-Bold", 14)
        p.drawString(inch, y_position, "SAHIHI NA MASHAHIDI")
        p.setFont("Helvetica", 10)
        y_position -= 30

        # Landlord Signature
        p.drawString(inch, y_position, "MKODISHAJI (LANDLORD):")
        p.line(inch + 1.5 * inch, y_position - 10, inch + 4 * inch, y_position - 10)
        p.drawString(inch + 1.5 * inch, y_position - 25, "Sahihi")
        p.line(inch + 4.5 * inch, y_position - 10, letter[0] - inch, y_position - 10)
        p.drawString(inch + 4.5 * inch, y_position - 25, "Tarehe")

        y_position -= 60

        # Tenant Signature
        p.drawString(inch, y_position, "MKODISHWA (TENANT):")
        p.line(inch + 1.5 * inch, y_position - 10, inch + 4 * inch, y_position - 10)
        p.drawString(inch + 1.5 * inch, y_position - 25, "Sahihi")
        p.line(inch + 4.5 * inch, y_position - 10, letter[0] - inch, y_position - 10)
        p.drawString(inch + 4.5 * inch, y_position - 25, "Tarehe")

        y_position -= 60

        # Witness 1
        p.drawString(inch, y_position, "SHAHIDI WA KWANZA:")
        p.line(inch + 1.5 * inch, y_position - 10, inch + 4 * inch, y_position - 10)
        p.drawString(inch + 1.5 * inch, y_position - 25, "Jina")
        p.line(inch + 4.5 * inch, y_position - 10, letter[0] - inch, y_position - 10)
        p.drawString(inch + 4.5 * inch, y_position - 25, "Sahihi")

        y_position -= 60

        # Witness 2
        p.drawString(inch, y_position, "SHAHIDI WA PILI:")
        p.line(inch + 1.5 * inch, y_position - 10, inch + 4 * inch, y_position - 10)
        p.drawString(inch + 1.5 * inch, y_position - 25, "Jina")
        p.line(inch + 4.5 * inch, y_position - 10, letter[0] - inch, y_position - 10)
        p.drawString(inch + 4.5 * inch, y_position - 25, "Sahihi")

        p.showPage()
        p.save()

        buffer.seek(0)
        response = HttpResponse(buffer, content_type='application/pdf')
        response['Content-Disposition'] = f'attachment; filename="Mkataba_wa_Kukodisha_Shamba_{farm_rent_contract.farm_number or farm_rent_contract.id}.pdf"'
        return response