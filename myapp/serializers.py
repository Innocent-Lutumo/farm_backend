from rest_framework import serializers
from django.contrib.auth.models import User
from .models import *
from django.core.exceptions import ValidationError
from django.core.validators import EmailValidator
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

class FarmRentSerializer(serializers.ModelSerializer):
    images = FarmImageSerializer(many=True, read_only=True)

    class Meta:
        model = FarmRent
        fields = '__all__' 


class FarmRentTransactionSerializer(serializers.ModelSerializer):
    farm = FarmRentSerializer(read_only=True)
    farm_id = serializers.PrimaryKeyRelatedField(
        queryset=FarmRent.objects.all(), write_only=True
    )

    class Meta:
        model = FarmRentTransaction
        fields = ['id', 'farm', 'farm_id', 'full_name', 'residence', 'national_id', 'renter_phone', 'transaction_id', 'renter_email', 'rent_date']

    def validate_renter_email(self, value):
        if not value:
            raise serializers.ValidationError("Renter email cannot be blank.")
        return value

    def create(self, validated_data):
        farm = validated_data.pop('farm_id')
        return FarmRentTransaction.objects.create(farm=farm, **validated_data)

class FarmSaleTransactionSerializer(serializers.ModelSerializer):
    farm = FarmSaleSerializer(read_only=True)
    farm_id = serializers.PrimaryKeyRelatedField(queryset=FarmSale.objects.all(), write_only=True)

    class Meta:
        model = FarmSaleTransaction
        fields = ['id', 'farm', 'farm_id', 'full_name', 'address', 'contact_info', 'national_id', 'intended_use', 'buyer_email', 'status', 'transaction_id']

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
    username = serializers.CharField(max_length=150)
    password = serializers.CharField(write_only=True)
    confirmPassword = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ['username', 'password', 'confirmPassword']

    def validate(self, data):
        if User.objects.filter(username=data['username']).exists():
            raise serializers.ValidationError("Username already exists.")
        if data['password'] != data['confirmPassword']:
            raise serializers.ValidationError("Password and Confirm Password do not match.")
        return data

    def create(self, validated_data):
        username = validated_data['username']
        password = validated_data['password']

        user = User.objects.create_user(
            username=username,
            password=password,
        )
        return user


    
