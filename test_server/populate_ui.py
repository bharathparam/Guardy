import requests
import os

BASE_URL = "http://localhost:8080"

print("Populating testing database for Dashboard visualization...")

# SAFE FILE
print("Uploading safe text file...")
requests.post(f"{BASE_URL}/upload", 
    data={"user_id": "test_safe_user"}, 
    files={"file": ("hello_world.txt", b"Hello, this is a very safe normal text file.", "text/plain")}
)

# THREAT FILE 1 
print("Uploading malicious mock exe as png...")
requests.post(f"{BASE_URL}/upload", 
    data={"user_id": "malicious_hacker"}, 
    files={"file": ("fake_image.png", b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xFF\xFF", "image/png")}
)

# THREAT FILE 2
print("Uploading high-entropy mock payload ...")
requests.post(f"{BASE_URL}/upload", 
    data={"user_id": "malicious_hacker"}, 
    files={"file": ("encrypted_virus.bin", os.urandom(1024 * 500), "application/octet-stream")}
)

print("Database population complete! You can view the dashboard.")
