import sys
import json
import hashlib
import requests
import boto3
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from urllib.parse import urlparse

def get_signed_sts_headers(endpoint, api_payload):
    # 1. Retrieve current credentials from standard provider chain
    session = boto3.Session()
    credentials = session.get_credentials().get_frozen_credentials()
    
    # 2. Extract website hostname for X-Auth-Server-Id
    parsed_url = urlparse(endpoint)
    hostname = parsed_url.hostname or "sts.amazonaws.com"
    
    # 3. Calculate SHA-256 hash of the custom API payload
    payload_json = json.dumps(api_payload)
    payload_hash = hashlib.sha256(payload_json.encode('utf-8')).hexdigest()
    
    # 4. Construct STS Request with both Server ID and Payload Hash headers
    url = "https://sts.amazonaws.com/"
    headers = {
        "Host": "sts.amazonaws.com",
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Auth-Server-Id": hostname,
        "X-Auth-Payload-Sha256": payload_hash
    }
    data = "Action=GetCallerIdentity&Version=2011-06-15"
    
    # 5. Cryptographically sign the request (SigV4)
    # The X-Auth-Server-Id and X-Auth-Payload-Sha256 headers are bound into the signature.
    request = AWSRequest(method="POST", url=url, headers=headers, data=data)
    region = session.region_name or "us-east-1"
    SigV4Auth(credentials, "sts", region).add_auth(request)
    
    signed_headers = dict(request.headers.items())
    
    return {
        "url": url,
        "method": "POST",
        "headers": signed_headers,
        "body": data
    }

if __name__ == "__main__":
    endpoint = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8788/AWSIAMIDENTITY"
    
    # Define a custom JSON payload we want to sign and send to our backend
    custom_payload = {
        "action": "create_user",
        "username": "alice",
        "role": "editor",
        "security_clearance": "level-2"
    }
    
    print(f"Generating signed STS headers with custom payload hash...")
    try:
        sts_payload = get_signed_sts_headers(endpoint, custom_payload)
    except Exception as e:
        print(f"Error getting AWS credentials: {e}")
        print("Please configure your AWS credentials first.")
        sys.exit(1)
        
    # Append the raw api_payload directly to the payload sent to the Worker
    sts_payload["api_payload"] = custom_payload
    
    print(f"Sending payload to endpoint: {endpoint}")
    print(f"Custom Payload body being sent: {json.dumps(custom_payload, indent=2)}")
    
    try:
        # Case A: Normal Verification (Success)
        print("\n--- Running Test 1: Legitimate Request (Should succeed) ---")
        response = requests.post(endpoint, json=sts_payload)
        print(f"Status Code: {response.status_code}")
        print("Response JSON:")
        print(json.dumps(response.json(), indent=2))
        
        # Case B: Tampering Attempt (Should fail)
        print("\n--- Running Test 2: Tampered Request (Should fail integrity check) ---")
        # Attacker modifies the payload data (e.g. changing the security clearance to level-5)
        tampered_payload = sts_payload.copy()
        tampered_payload["api_payload"] = {
            "action": "create_user",
            "username": "alice",
            "role": "editor",
            "security_clearance": "level-5" # <-- Tampered!
        }
        
        response_tampered = requests.post(endpoint, json=tampered_payload)
        print(f"Status Code: {response_tampered.status_code}")
        print("Response:")
        try:
            print(json.dumps(response_tampered.json(), indent=2))
        except Exception:
            print(response_tampered.text)
            
    except Exception as e:
        print(f"Failed to connect to endpoint: {e}")
