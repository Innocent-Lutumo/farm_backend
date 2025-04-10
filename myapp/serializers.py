from rest_framework import serializers
from django.contrib.auth.models import User
from .models import *

class FarmSaleSerializer(serializers.ModelSerializer):
    class Meta:
        model = FarmSale
        fields = '__all__'

class FarmRentSerializer(serializers.ModelSerializer):
    class Meta:
        model = FarmRent
        fields = '__all__'



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


    
