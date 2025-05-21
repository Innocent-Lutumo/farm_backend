# from rest_framework.views import APIView
# from rest_framework.response import Response
# from rest_framework import status
# from django.contrib.auth import authenticate
# from rest_framework_simplejwt.tokens import RefreshToken
# from django.contrib.auth import get_user_model
# from rest_framework_simplejwt.views import TokenObtainPairView
# from .serializers import CustomTokenObtainPairSerializer

# User = get_user_model()

# class CustomTokenObtainPairView(TokenObtainPairView):
#     serializer_class = CustomTokenObtainPairSerializer

# class LoginView(APIView):
#     def post(self, request):
#         username = request.data.get("username")
#         password = request.data.get("password")

#         if not username or not password:
#             return Response({"error": "Username and password are required"}, status=status.HTTP_400_BAD_REQUEST)

#         user = authenticate(request, username=username, password=password)

#         if user is None:
#             return Response({"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)

#         if not user.is_active:
#             return Response({"error": "This account is inactive"}, status=status.HTTP_403_FORBIDDEN)

#         refresh = RefreshToken.for_user(user)

#         return Response({
#             "access": str(refresh.access_token),
#             "refresh": str(refresh),
#             "user": {
#                 "id": user.id,
#                 "username": user.username,
#                 "email": user.email,
#                 "full_name": getattr(user, "full_name", ""),
#                 "role": getattr(user, "role", ""),
#                 "seller_name": getattr(user, "seller_name", ""),
#                 "seller_residence": getattr(user, "seller_residence", ""),
#             }
#         }, status=status.HTTP_200_OK)
