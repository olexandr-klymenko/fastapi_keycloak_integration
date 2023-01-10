import os

KEYCLOAK_URL = os.getenv("KEYCLOAK_URL", "http://127.0.0.1:8080/auth")
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
REALM = os.getenv("REALM")
CLOUD_ADMIN_ROLE = os.getenv("CLOUD_ADMIN_ROLE", "cloud_admin")
CALLBACK_URI = os.getenv("CALLBACK_URI", "http://localhost:8081/callback")