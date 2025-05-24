from rest_framework import serializers
from django.contrib.auth.models import User
from .models import *  
from django.core.exceptions import ValidationError
from django.core.validators import EmailValidator
import os
import re
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer


class FarmImageSerializer(serializers.ModelSerializer):
    class Meta:
        model = FarmImage
        fields = ['image']

class FarmSaleSerializer(serializers.ModelSerializer):
    images = FarmImageSerializer(many=True, read_only=True)

    class Meta:
        model = FarmSale
        fields = '__all__'

    def validate_passport(self, value):
        # Validate max size (2MB for passport photo)
        max_size = 1 * 1024 * 1024
        if value.size > max_size:
            raise serializers.ValidationError("Passport photo must be 1MB or smaller.")

        # Validate file type
        valid_mime_types = ['image/jpeg', 'image/png']
        content_type = getattr(value, 'content_type', None)
        if content_type not in valid_mime_types:
            raise serializers.ValidationError("Passport must be a JPEG or PNG image.")

        # Optional: Validate file extension
        ext = os.path.splitext(value.name)[1].lower()
        if ext not in ['.jpg', '.jpeg', '.png']:
            raise serializers.ValidationError("Invalid passport file extension.")

        return value

    def validate_ownership_certificate(self, value):
        # Validate max size (5MB for certificates)
        max_size = 5 * 1024 * 1024
        if value.size > max_size:
            raise serializers.ValidationError("Certificate file size must be 5MB or smaller.")

        # Only allow PDF files
        content_type = getattr(value, 'content_type', None)
        if content_type != 'application/pdf':
            raise serializers.ValidationError("Certificate must be a PDF file.")

        ext = os.path.splitext(value.name)[1].lower()
        if ext != '.pdf':
            raise serializers.ValidationError("Certificate file must have a .pdf extension.")

        return value

    def validate_farm_number(self, value):
        # Must match pattern: digits-hyphen-letters (e.g., 45-sinza)
        if not re.match(r'^\d+-[a-zA-Z]+$', value):
            raise serializers.ValidationError("Farm number must be in the format '45-sinza'.")
        return value
    
class FarmRentSerializer(serializers.ModelSerializer):
    images = FarmImageSerializer(many=True, read_only=True)

    class Meta:
        model = FarmRent
        fields = '__all__' 

    def validate_passport(self, value):
        # Validate file size (e.g., max 5MB)
        max_size = 5 * 1024 * 1024  # 5 MB
        if value.size > max_size:
            raise serializers.ValidationError("Passport file size must be <= 5MB")

        # Validate file type: allow PDF or images
        valid_mime_types = ['application/pdf', 'image/jpeg', 'image/png', 'image/jpg']
        if value.content_type not in valid_mime_types:
            raise serializers.ValidationError("Passport must be a PDF or image file")

        return value

    def validate_ownership_certificate(self, value):
        max_size = 5 * 1024 * 1024  # 5 MB
        if value.size > max_size:
            raise serializers.ValidationError("Certificate file size must be <= 5MB")

        valid_mime_types = ['application/pdf', 'image/jpeg', 'image/png', 'image/jpg']
        if value.content_type not in valid_mime_types:
            raise serializers.ValidationError("Certificate must be a PDF or image file")

        return value


class FarmRentTransactionSerializer(serializers.ModelSerializer):
    farm = FarmRentSerializer(read_only=True)
    farm_id = serializers.PrimaryKeyRelatedField(
        queryset=FarmRent.objects.all(), write_only=True
    )

    class Meta:
        model = FarmRentTransaction
        fields = '__all__' 

    def validate_renter_email(self, value):
        if not value:
            raise serializers.ValidationError("Renter email cannot be blank.")
        return value

    def create(self, validated_data):
        farm = validated_data.pop('farm_id')
        validated_data['is_rented'] = True  
        return FarmRentTransaction.objects.create(farm=farm, **validated_data)

class FarmSaleTransactionSerializer(serializers.ModelSerializer):
    farm = FarmSaleSerializer(read_only=True)
    farm_id = serializers.PrimaryKeyRelatedField(queryset=FarmSale.objects.all(), write_only=True)

    class Meta:
        model = FarmSaleTransaction
        fields = '__all__'

    def validate_buyer_email(self, value):
        if not value:
            raise serializers.ValidationError("Buyer email cannot be blank.")
        try:
            EmailValidator()(value)
        except ValidationError:
            raise serializers.ValidationError("Enter a valid email address.")
        return value

    def create(self, validated_data):
        farm = validated_data.pop('farm_id', None)
        if not farm:
            raise serializers.ValidationError("Farm ID is required.")
        return FarmSaleTransaction.objects.create(farm=farm, **validated_data)

class CombinedFarmSerializer(serializers.Serializer):
    type = serializers.CharField()
    data = serializers.DictField()

class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    def validate(self, attrs):
        data = super().validate(attrs)
        data.update({
            'user': {
                'id': self.user.id,
                'username': self.user.username,
            }
        })
        
        return data
 
class RegisterSerializer(serializers.ModelSerializer):
    seller_name = serializers.CharField(max_length=150)
    username = serializers.CharField(max_length=150)
    seller_residence = serializers.CharField(max_length=255)
    password = serializers.CharField(write_only=True, style={'input_type': 'password'})
    confirmPassword = serializers.CharField(write_only=True, style={'input_type': 'password'})
    
    class Meta:
        model = User
        fields = ['seller_name', 'username', 'seller_residence', 'password', 'confirmPassword']
    
    def validate(self, data):
        if User.objects.filter(username=data['username']).exists():
            raise serializers.ValidationError("Username already exists.")
        if data['password'] != data['confirmPassword']:
            raise serializers.ValidationError("Password and Confirm Password do not match.")
        return data
    
    def create(self, validated_data):
        validated_data.pop('confirmPassword', None)

        seller_name = validated_data.pop('seller_name')
        seller_residence = validated_data.pop('seller_residence')
        user = User.objects.create_user(**validated_data)
        user.first_name = seller_name
        user.save()
        return user
   
    def update(self, instance, validated_data):
        validated_data.pop('confirmPassword', None)
        if 'seller_name' in validated_data:
            instance.first_name = validated_data.pop('seller_name')
       
        if 'username' in validated_data:
            instance.username = validated_data.pop('username')
        
        if 'password' in validated_data:
            instance.set_password(validated_data.pop('password'))
        instance.save()
        if 'seller_residence' in validated_data:
            seller_residence = validated_data.pop('seller_residence')
        return instance
    




    
