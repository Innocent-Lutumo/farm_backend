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
    username = serializers.CharField(source='user.username', read_only=True)
    farm_number = serializers.CharField(allow_blank=True, required=False)
    
    passport = serializers.FileField(
        use_url=True,
        required=False,
        allow_null=True
    )

    ownership_certificate = serializers.FileField(
        use_url=True,
        required=False,
        allow_null=True
    )

    class Meta:
        model = FarmSale
        fields = '__all__'

    def to_representation(self, instance):
        ret = super().to_representation(instance)
        farm_num = ret.get('farm_number', '')
        if not farm_num or farm_num.strip().upper() == "UNKNOWN":
            ret['farm_number'] = "Not provided"
        return ret

    def validate_passport(self, value):
        if not value:
            return value  # Skip if optional and not provided

        max_size = 3 * 1024 * 1024  # 3MB
        valid_mime_types = ['image/jpeg', 'image/png']
        valid_extensions = ['.jpg', '.jpeg', '.png']

        content_type = getattr(value, 'content_type', '').lower()
        extension = os.path.splitext(value.name)[1].lower()

        if value.size > max_size:
            raise serializers.ValidationError("Passport photo must be 3MB or smaller.")
        if content_type not in valid_mime_types:
            raise serializers.ValidationError("Passport must be a JPEG or PNG image.")
        if extension not in valid_extensions:
            raise serializers.ValidationError("Invalid passport file extension. Allowed: .jpg, .jpeg, .png")

        return value

    def validate_ownership_certificate(self, value):
        if not value:
            return value  # Skip if optional and not provided

        max_size = 5 * 1024 * 1024  # 5MB
        valid_mime_types = ['application/pdf', 'image/jpeg', 'image/png']
        valid_extensions = ['.pdf', '.jpg', '.jpeg', '.png']

        content_type = getattr(value, 'content_type', '').lower()
        extension = os.path.splitext(value.name)[1].lower()

        if value.size > max_size:
            raise serializers.ValidationError("Certificate file size must be 5MB or smaller.")
        if content_type not in valid_mime_types:
            raise serializers.ValidationError("Certificate must be a PDF or image file (PDF, JPG, PNG).")
        if extension not in valid_extensions:
            raise serializers.ValidationError("Certificate file extension must be one of: .pdf, .jpg, .jpeg, .png")

        return value

    # Validate farm number format (e.g., 45-sinza)
    def validate_farm_number(self, value):
        if not re.match(r'^\d+-[a-zA-Z]+$', value):
            raise serializers.ValidationError("Farm number must be in the format '45-sinza'.")
        return value
    
class FarmRentSerializer(serializers.ModelSerializer):
    images = FarmImageSerializer(many=True, read_only=True)
    username = serializers.CharField(source='user.username', read_only=True)
    farm_number = serializers.CharField(allow_blank=True, required=False)
    
    passport = serializers.FileField(
        use_url=True,
        required=False,
        allow_null=True
    )
    ownership_certificate = serializers.FileField(
        use_url=True,
        required=False,
        allow_null=True
    )

    class Meta:
        model = FarmRent
        fields = '__all__'

    def to_representation(self, instance):
        ret = super().to_representation(instance)
        farm_num = ret.get('farm_number', '')
        if not farm_num or farm_num.strip().upper() == "UNKNOWN":
            ret['farm_number'] = "Not provided"
        return ret

    def validate_passport(self, value):
        if not value:
            return value  # Optional: skip validation if not provided

        max_size = 5 * 1024 * 1024  # 5MB
        valid_mime_types = ['application/pdf', 'image/jpeg', 'image/png']
        valid_extensions = ['.pdf', '.jpg', '.jpeg', '.png']

        content_type = getattr(value, 'content_type', '').lower()
        extension = os.path.splitext(value.name)[1].lower()

        if value.size > max_size:
            raise serializers.ValidationError("Passport file size must be 5MB or smaller.")
        if content_type not in valid_mime_types:
            raise serializers.ValidationError("Passport must be a PDF or image file.")
        if extension not in valid_extensions:
            raise serializers.ValidationError("Invalid passport file extension. Allowed: .pdf, .jpg, .jpeg, .png")

        return value

    def validate_ownership_certificate(self, value):
        if not value:
            return value  

        max_size = 5 * 1024 * 1024  # 5MB
        valid_mime_types = ['application/pdf', 'image/jpeg', 'image/png']
        valid_extensions = ['.pdf', '.jpg', '.jpeg', '.png']

        content_type = getattr(value, 'content_type', '').lower()
        extension = os.path.splitext(value.name)[1].lower()

        if value.size > max_size:
            raise serializers.ValidationError("Certificate file size must be 5MB or smaller.")
        if content_type not in valid_mime_types:
            raise serializers.ValidationError("Certificate must be a PDF or image file.")
        if extension not in valid_extensions:
            raise serializers.ValidationError("Invalid certificate file extension. Allowed: .pdf, .jpg, .jpeg, .png")

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
        # Include your new fields directly in Meta.fields
        fields = ['id', 'seller_name', 'username', 'seller_residence', 'password', 'confirmPassword']
        extra_kwargs = {'password': {'write_only': True}, 'confirmPassword': {'write_only': True}} # Good practice

    def validate(self, data):
        # Your existing validation logic
        if User.objects.filter(username=data['username']).exists():
            raise serializers.ValidationError("Username already exists.")
        if data['password'] != data['confirmPassword']:
            raise serializers.ValidationError("Password and Confirm Password do not match.")
        return data
    
    def create(self, validated_data):
        validated_data.pop('confirmPassword', None)
        
        # Assign directly to the new model fields
        seller_name = validated_data.pop('seller_name')
        seller_residence = validated_data.pop('seller_residence')
        
        # Use create_user to handle password hashing
        user = User.objects.create_user(**validated_data) 
        
        # Now assign to the custom fields on your User model
        user.seller_name = seller_name
        user.seller_residence = seller_residence
        user.save() # Save the user after setting the custom fields
        
        return user
    
    def update(self, instance, validated_data):
        validated_data.pop('confirmPassword', None)

        # Update custom fields if provided
        if 'seller_name' in validated_data:
            instance.seller_name = validated_data.pop('seller_name')
        
        if 'seller_residence' in validated_data:
            instance.seller_residence = validated_data.pop('seller_residence')
        
        # Update username if provided
        if 'username' in validated_data:
            instance.username = validated_data.pop('username')
        
        # Update password if provided
        if 'password' in validated_data:
            instance.set_password(validated_data.pop('password'))
            
        instance.save() # Save changes to the instance
        return instance
    




    
