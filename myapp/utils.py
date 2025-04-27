import google.auth
import requests

def verify_google_token(token):
    try:
        # Verifying token with Google
        response = requests.get(f'https://www.googleapis.com/oauth2/v3/tokeninfo?id_token={token}')
        user_info = response.json()
        
        if response.status_code != 200:
            raise ValueError("Invalid Google token")

        return user_info
    except Exception as e:
        raise ValueError("Invalid Google token", e)
