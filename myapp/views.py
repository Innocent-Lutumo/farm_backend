from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from .models import FarmSale, FarmRent
from .serializers import *
from rest_framework import status
from rest_framework.decorators import api_view
# Create your views here.

@api_view(['POST'])
def upload_farm(request):
    if request.method == 'POST':
        # Get the data from the request
        data = request.data
        # Process the data (e.g., save it to the database)
        
        return Response({'message': 'Farm uploaded successfully!'}, status=200)
    else:
        return Response({'error': 'Invalid request method'}, status=400)
    
class RegisterView(APIView):
    def post(self, request):
        serializers = RegisterSerializer(data = request.data)
        if serializers.is_valid():
            serializers.save()
            return Response({"message": "User registered successfully"}, status=status.HTTP_201_CREATED)
        return Response(serializers.errors, status=status.HTTP_400_BAD_REQUEST)

class UploadFarmAPIView(APIView):
    def post(self, request, *args, **kwargs):
        farm_type = request.data.get("farmType")
        
        if farm_type == "Sale":
            serializer = FarmSaleSerializer(data=request.data)
        elif farm_type == "Rent":
            serializer = FarmRentSerializer(data=request.data)
        else:
            return Response({"error": "Invalid farm type"}, status=status.HTTP_400_BAD_REQUEST)
        
        if serializer.is_valid():
            serializer.save()
            return Response({"message": f"Farm uploaded successfully for {farm_type}!"}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
