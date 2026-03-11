import requests
import io
import time

BASE_URL = "http://localhost:8080"

print("--- Testing Configurable Risk Engine ---")

# 1. Test Strict Entropy Configuration
# We will create a highly random byte array that simulates an encrypted payload.
# Since our custom config set 'max_safe_entropy=7.5', a truly random 1MB file will easily exceed this.

print("\n1. Generating Encrypted/Random Payload (High Entropy)...")
import os
random_bytes = os.urandom(1024 * 1024)  # 1MB of pure random data

files = {
    'file': ('encrypted_payload.bin', random_bytes, 'application/octet-stream')
}
data = {
    'user_id': 'hacker_bob'
}

print("Uploading to /upload...")
response = requests.post(f"{BASE_URL}/upload", files=files, data=data)

if response.status_code == 200:
    print("Response Received (SAFE):")
    print(response.json())
else:
    print(f"Error ({response.status_code}): {response.text}")

# 2. Test MIME Spoofing Penalty
print("\n2. Generating MIME Spoofed Payload...")
files = {
    'file': ('innocent.exe', b"This is just plain text simulating an executable extension.", 'text/plain')
}
data = {
    'user_id': 'tricky_alice'
}

print("Uploading to /upload...")
response = requests.post(f"{BASE_URL}/upload", files=files, data=data)

if response.status_code == 200:
    print("Response Received (SAFE):")
    print(response.json())
else:
    print(f"Error ({response.status_code}): {response.text}")
