import google.auth
import requests
from django.contrib.auth import get_user_model
# utils.py
import os
from io import BytesIO
from datetime import datetime
from django.conf import settings

def verify_google_token(token):
    try:
        # Verifying token with Google
        response = requests.get(f'https://www.googleapis.com/oauth2/v3/tokeninfo?id_token={token}')
        user_info = response.json()

        if response.status_code != 200:
            raise ValueError("Invalid Google token")

        return user_info
    except Exception as e:
        raise ValueError("Invalid Google token") from e

def some_user_function():
    User = get_user_model()
    user = User.objects.filter(is_active=True).first()
    if not user:
        raise ValueError("No active user found in the database.")
    return user.id
