from rest_framework.views import APIView
from rest_framework.response import Response
from .models import FarmSale, FarmRent, FarmRentTransaction, FarmImage 
from .serializers import FarmSaleSerializer, FarmRentSerializer
from .serializers import *
from rest_framework import status
from rest_framework.decorators import api_view
from rest_framework_simplejwt.views import TokenObtainPairView
from .serializers import CustomTokenObtainPairSerializer
from .serializers import FarmRentTransactionSerializer, FarmSaleTransactionSerializer
from django.core.mail import send_mail
from rest_framework import viewsets
from django.http import JsonResponse
import json
from django.views.decorators.csrf import csrf_exempt
import requests
from .utils import verify_google_token

@csrf_exempt  
def google_login_view(request):
    if request.method == 'POST':
        try:
            body = json.loads(request.body)
            token = body.get('token')
            
            if not token:
                return JsonResponse({"error": "Token is missing"}, status=400)

            user_info = verify_google_token(token) 

            return JsonResponse({"message": "Google login successful", "user_info": user_info})

        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON format"}, status=400)

        except Exception as e:
            return JsonResponse({"error": "Google login failed", "message": str(e)}, status=500)
    
    else:
        return JsonResponse({"error": "Invalid request method"}, status=405)


# obtain token for user
class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer

# This is a simple view to register a user
class RegisterView(APIView):
    def post(self, request):
        serializers = RegisterSerializer(data = request.data)
        if serializers.is_valid():
            serializers.save()
            return Response({"message": "User registered successfully"}, status=status.HTTP_201_CREATED)
        return Response(serializers.errors, status=status.HTTP_400_BAD_REQUEST)

#  Accepts POST data, validates it using a serializer, and saves the transaction if valid.
@api_view(['POST'])
def create_rent_transaction(request):
    serializer = FarmRentTransactionSerializer(data=request.data)
    if serializer.is_valid():
        try:
            serializer.save()
            return Response(serializer.data, status=201)
        except Exception as e:
            print("Unexpected save() error:", e)
            return Response({"detail": "Internal error during save"}, status=500)
    print("Validation errors:", serializer.errors)
    return Response(serializer.errors, status=400)

@api_view(['POST'])
def create_sale_transaction(request):
    serializer = FarmSaleTransactionSerializer(data=request.data)
    if serializer.is_valid():
        try:
            serializer.save()
            return Response(serializer.data, status=201)
        except Exception as e:
            return Response({"detail": "Internal error during save"}, status=500)
    return Response({"errors": serializer.errors}, status=400)


@api_view(['GET'])
def get_transactions(request):
    transactions = FarmRentTransaction.objects.select_related('farm').all()
    serializer = FarmRentTransactionSerializer(transactions, many=True)
    return Response(serializer.data)

@api_view(['GET'])
def sale_transactions(request):
    transactions = FarmSaleTransaction.objects.select_related('farm').all()
    serializer = FarmSaleTransactionSerializer(transactions, many=True)
    return Response(serializer.data)

# This is a simple view to get the details of a farm for sale
@api_view(['GET'])
def get_farms(request):
    farms = FarmSale.objects.all()
    serializer = FarmSaleSerializer(farms, many=True)
    return Response(serializer.data)

# This is a simple view to get the details of a farm for rent
@api_view(['GET'])
def get_rent_farms(request):
    farm_type = request.GET.get('type', None)
    if farm_type:
        farms = FarmRent.objects.filter(farm_type__iexact=farm_type)
    else:
        farms = FarmRent.objects.all()
    serializer = FarmRentSerializer(farms, many=True)
    return Response(serializer.data)

# This is a simple view to get the details of a farm for sale
@api_view(['GET'])
def sale_farm_detail(request, id):
    try:
        farm = FarmSale.objects.get(pk=id)
    except FarmSale.DoesNotExist:
        return Response({"error": "Farm not found."}, status=status.HTTP_404_NOT_FOUND)

    serializer = FarmSaleSerializer(farm)
    return Response(serializer.data)

# This is a simple view to get the details of a farm for rent
@api_view(['GET'])
def rent_farm_rent(request, id):
    try:
        farm = FarmRent.objects.get(pk=id)
    except FarmRent.DoesNotExist:
        return Response({"error": "Farm not found."}, status=status.HTTP_404_NOT_FOUND)

    serializer = FarmRentSerializer(farm)
    return Response(serializer.data)
    


# This is a simple view to upload a farm
class UploadFarmAPIView(APIView):
    def post(self, request, *args, **kwargs):
        farm_type = request.data.get("farmType")
        images = request.FILES.getlist('images')  # ✅ Match frontend

        # Validate number of images
        if len(images) < 3 or len(images) > 10:
            return Response(
                {"error": "You must upload between 3 and 10 images."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Choose appropriate serializer
        if farm_type == "Sale":
            serializer = FarmSaleSerializer(data=request.data)
        elif farm_type == "Rent":
            serializer = FarmRentSerializer(data=request.data)
        else:
            return Response({"error": "Invalid farm type"}, status=status.HTTP_400_BAD_REQUEST)

        if serializer.is_valid():
            farm_instance = serializer.save()

            # Save each image
            for img in images:
                FarmImage.objects.create(
                    farm_sale=farm_instance if farm_type == "Sale" else None,
                    farm_rent=farm_instance if farm_type == "Rent" else None,
                    image=img
                )

            return Response({"message": f"Farm uploaded successfully for {farm_type}!"}, status=status.HTTP_201_CREATED)

        print(serializer.errors)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# This is a simple view to get all farms    
class AllFarmsView(APIView):
    def get(self, request):
        sales = FarmSale.objects.all()
        rents = FarmRent.objects.all()

        sale_data = [
            {"type": "Sale", "data": FarmSaleSerializer(sale).data}
            for sale in sales
        ]
        rent_data = [
            {"type": "Rent", "data": FarmRentSerializer(rent).data}
            for rent in rents
        ]

        combined = sale_data + rent_data
        return Response(combined)

class FarmDetailView(APIView):
    def get(self, request, farm_id):
        # Try to find the farm in sales first
        try:
            farm = FarmSale.objects.get(id=farm_id)
            serializer = FarmSaleSerializer(farm)
            return Response(serializer.data)
        except FarmSale.DoesNotExist:
            pass

        # If not found in sales, try rents
        try:
            farm = FarmRent.objects.get(id=farm_id)
            serializer = FarmRentSerializer(farm)
            return Response(serializer.data)
        except FarmRent.DoesNotExist:
            return Response(
                {"error": "Farm not found"},
                status=status.HTTP_404_NOT_FOUND
            )


# This is a simple view to send an email with the transaction ID    
@api_view(['POST'])
def send_transaction_email(request):
    email = request.data.get('buyer_email')
    transaction_id = request.data.get('transaction_id')

    if not email or not transaction_id:
        return Response(
            {'error': 'Missing required fields (buyer_email, transaction_id).'},
            status=status.HTTP_400_BAD_REQUEST
        )

    try:
        # Send email logic
        send_mail(
            subject='Your Transaction ID from Farm Finder',
            message=f'Thank you for your purchase! Your transaction ID is: {transaction_id}',
            from_email='yourapp@example.com',
            recipient_list=[email],
            fail_silently=False,
        )

        return Response({'message': 'Email sent successfully.'}, status=status.HTTP_200_OK)
    except Exception as e:
        return Response({'error': f'Failed to send email: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



class TransactionViewSet(viewsets.ModelViewSet):
    queryset = FarmRentTransaction.objects.all()
    serializer_class = FarmRentTransactionSerializer

class SaleTransactionViewSet(viewsets.ModelViewSet):
    queryset = FarmSaleTransaction.objects.all()
    serializer_class = FarmSaleTransactionSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)

        return Response(serializer.data, status=status.HTTP_201_CREATED)
    
    # Example of adding a custom delete response
    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        self.perform_destroy(instance)
        return Response({"message": "Transaction successfully deleted."}, status=204)
    
    def perform_destroy(self, instance):
        instance.delete()

