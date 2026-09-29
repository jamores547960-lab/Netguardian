"""
NetGuardian – Gmail OAuth2 Token Helper
========================================
Run this script ONCE to get your refresh token, then paste the values into .env.

Usage:
    python get_gmail_token.py

Requirements:
    pip install google-auth google-auth-oauthlib

Steps before running:
  1. Go to https://console.cloud.google.com/
  2. Create a project → Enable "Gmail API"
  3. OAuth consent screen → External → add your Gmail as a test user
  4. Credentials → Create OAuth 2.0 Client ID → Desktop App → Download JSON
  5. Save the downloaded file as  client_secret.json  in this folder
  6. Run this script – a browser window will open for you to log in
  7. Copy the printed values into your .env file
"""

import json
import os

try:
    from google_auth_oauthlib.flow import InstalledAppFlow
except ImportError:
    print("ERROR: Run:  pip install google-auth-oauthlib")
    raise SystemExit(1)

SCOPES = ['https://www.googleapis.com/auth/gmail.send']
SECRET_FILE = os.path.join(os.path.dirname(__file__), 'client_secret.json')

if not os.path.exists(SECRET_FILE):
    print(f"\nERROR: '{SECRET_FILE}' not found.")
    print("Download your OAuth 2.0 client credentials JSON from Google Cloud Console")
    print("and save it as 'client_secret.json' in the NetGuardian project folder.\n")
    raise SystemExit(1)

print("\n[1/3] Opening browser for Google login …")
flow = InstalledAppFlow.from_client_secrets_file(SECRET_FILE, scopes=SCOPES)
creds = flow.run_local_server(port=0, prompt='consent', access_type='offline')

with open(SECRET_FILE) as f:
    secret_data = json.load(f)

client_info = secret_data.get('installed') or secret_data.get('web', {})
client_id     = client_info.get('client_id', '')
client_secret = client_info.get('client_secret', '')
refresh_token = creds.refresh_token

print("\n[2/3] Authentication successful!\n")
print("=" * 60)
print("Copy these three lines into your .env file:")
print("=" * 60)
print(f"NETGUARDIAN_GMAIL_CLIENT_ID={client_id}")
print(f"NETGUARDIAN_GMAIL_CLIENT_SECRET={client_secret}")
print(f"NETGUARDIAN_GMAIL_REFRESH_TOKEN={refresh_token}")
print("=" * 60)
print("\n[3/3] Done. You can delete client_secret.json after saving the values.\n")
