# # serializers.py
# from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
# from rest_framework import serializers

# class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
#     @classmethod
#     def get_token(cls, user):
#         token = super().get_token(user)
#         # Add extra claims
#         token["username"] = user.username
#         token["role"] = user.role
#         token["email"] = user.email
#         return token

#     def validate(self, attrs):
#         data = super().validate(attrs)
#         data["user"] = {
#             "id": self.user.id,
#             "username": self.user.username,
#             "email": self.user.email,
#             "full_name": self.user.full_name,
#             "role": self.user.role,
#             "seller_name": self.user.seller_name,
#             "seller_residence": self.user.seller_residence,
#         }
#         return data
