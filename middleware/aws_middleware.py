from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from utils.aws_auth import assume_role
import json

with open("config.json", "r") as config_file:
    config = json.load(config_file)
    
# Access the first element if config is a list
if isinstance(config, list):
    config = config[0]

aws_account_id = config.get("account_id")
aws_role_name = config.get("role_name")

class AWSRoleMiddleware(BaseHTTPMiddleware):
    """
    Middleware to validate AWS role and credentials for each request.
    """
    async def dispatch(self, request: Request, call_next):
        if not aws_role_name:
            raise HTTPException(status_code=400, detail="Missing AWS Role Name in config")
        if not aws_account_id:
            raise HTTPException(status_code=400, detail="Missing AWS Account ID in config")

        try:
            role_arn = f"arn:aws:iam::{aws_account_id}:role/{aws_role_name}"

            credentials = assume_role(role_arn, session_name="api-session")
            request.state.aws_credentials = credentials
        except Exception as e:
            raise HTTPException(status_code=403, detail=f"Failed to assume AWS role: {str(e)}")

        response = await call_next(request)
        return response