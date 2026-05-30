import os
import json
import urllib3
import boto3
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest

def lambda_handler(event, context):
    """
    AWS Lambda function handler that authenticates to a custom Cloudflare Pages 
    endpoint (/AWSIAMIDENTITY) using the Lambda execution role's identity.
    
    Expects input event to contain "website_url" (optional).
    Falls back to the environment variable "WEBSITE_URL" (optional).
    """
    
    # 1. Resolve the target website endpoint URL from inputs
    website_url = event.get("website_url") or os.environ.get("WEBSITE_URL")
    
    if not website_url:
        return {
            "statusCode": 400,
            "body": {
                "error": "Missing website URL. Please provide 'website_url' in the event payload or set the 'WEBSITE_URL' environment variable."
            }
        }
        
    print(f"Target verification endpoint: {website_url}")

    # 2. Get current Lambda execution role credentials
    session = boto3.Session()
    credentials = session.get_credentials()
    if not credentials:
        return {
            "statusCode": 500,
            "body": {"error": "Failed to retrieve AWS credentials from the Lambda environment."}
        }
    frozen_credentials = credentials.get_frozen_credentials()
    
    # 3. Construct a standard AWS STS GetCallerIdentity request
    # This request will be signed but not executed directly from the Lambda.
    sts_url = "https://sts.amazonaws.com/"
    headers = {
        "Host": "sts.amazonaws.com",
        "Content-Type": "application/x-www-form-urlencoded"
    }
    body_data = "Action=GetCallerIdentity&Version=2011-06-15"
    
    # 4. Sign the request using Signature Version 4 (SigV4)
    # The signature is scoped to the 'sts' service and the default region 'us-east-1'.
    aws_request = AWSRequest(method="POST", url=sts_url, headers=headers, data=body_data)
    SigV4Auth(frozen_credentials, "sts", "us-east-1").add_auth(aws_request)
    
    # Convert headers from AWSRequest to a standard Python dictionary
    signed_headers = dict(aws_request.headers.items())
    
    # 5. Build payload to send to the Cloudflare Worker
    payload = {
        "url": sts_url,
        "method": "POST",
        "headers": signed_headers,
        "body": body_data
    }
    
    # 6. POST the payload to the Cloudflare Workers/Pages endpoint
    # We use urllib3 (pre-installed in Python Lambda runtimes) to avoid any external dependencies.
    http = urllib3.PoolManager()
    try:
        response = http.request(
            "POST",
            website_url,
            body=json.dumps(payload),
            headers={"Content-Type": "application/json"}
        )
        
        response_text = response.data.decode("utf-8")
        print(f"Response Status: {response.status}")
        print(f"Response Body: {response_text}")
        
        # Check if the verification succeeded
        try:
            response_json = json.loads(response_text)
        except json.JSONDecodeError:
            response_json = {"raw_response": response_text}
            
        return {
            "statusCode": response.status,
            "body": response_json
        }
        
    except Exception as e:
        print(f"Failed to call endpoint: {e}")
        return {
            "statusCode": 500,
            "body": {"error": "Failed to connect to the website endpoint.", "details": str(e)}
        }
