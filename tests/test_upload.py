import pytest
from fastapi.testclient import TestClient
import io

# We need to set the environment variable before importing the app
import os
os.environ["MONGO_URI"] = "mongodb://localhost:27017" # Default local

from app.main import app
from guardy.validation.signature import MAGIC_SIGNATURES

client = TestClient(app)

def test_safe_upload():
    # A valid fake JPEG based on Magic bytes
    file_bytes = MAGIC_SIGNATURES["image/jpeg"][0] + b"fakejpegdata123"
    
    response = client.post(
        "/upload",
        data={"user_id": "test_user_1"},
        files={"file": ("test_image.jpg", file_bytes, "image/jpeg")}
    )
    
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "SUCCESS"
    assert "file_id" in data

def test_spoofed_upload():
    # A text file masquerading as a JPEG (MIME or signature spoof)
    file_bytes = b"This is just plain text content."
    
    response = client.post(
        "/upload",
        data={"user_id": "test_hacker"},
        # We tell FastAPI it's an image, but it's really text
        files={"file": ("fake_image.jpg", file_bytes, "image/jpeg")}
    )
    
    # Due to python-magic, the analyzer detects 'text/plain' 
    # and the signature fails for jpeg. It should be blocked.
    assert response.status_code == 403
    data = response.json()
    assert data["status"] == "BLOCKED"
    assert "reasons" in data
    # We verify one of our checks fired
    assert len(data["reasons"]) > 0

def test_polyglot_upload():
    # A valid sequence for a generic mime but contains malicious PHP
    file_bytes = MAGIC_SIGNATURES["image/jpeg"][0] + b"fake_image_data <?php system('id'); ?> text file payload"
    
    response = client.post(
        "/upload",
        data={"user_id": "test_hacker_2"},
        # Let's say it's an image to bypass basic checks
        files={"file": ("evil.jpg", file_bytes, "image/jpeg")}
    )
    
    assert response.status_code == 403
    data = response.json()
    assert data["status"] == "BLOCKED"
    
def test_dashboard_mount():
    # Verify the dashboard is accessible
    response = client.get("/security-dashboard/")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "File Security Dashboard" in response.text
