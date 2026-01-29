import json
import sys
import traceback
import os
import re
from typing import Optional, Dict, Any
from utils.response_formatter import format_response
from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from utils.aws_auth import assume_role
import logging

logger = logging.getLogger(__name__)

# Load the config file with error handling and absolute path
config_path = os.path.join(os.path.dirname(__file__), '..', 'config.json')
try:
    with open(config_path, "r") as config_file:
        config = json.load(config_file)
except Exception as e:
    print(f"Error loading config.json from {config_path}: {e}")
    config = []


# Define class-based middleware
class AWSMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        try:
            # Skip AWS middleware for OPTIONS requests (CORS preflight)
            if request.method == "OPTIONS":
                return await call_next(request)

            # Skip AWS middleware for these paths (they don't need AWS account validation)
            if request.url.path in ["/docs", "/favicon", "/openapi.json", "/health"] or \
               request.url.path.startswith("/api/auth") or \
               request.url.path.startswith("/api/dashboard"):
                return await call_next(request)

            aws_account_id = None
            if "/api/" in request.url.path:
                query_params = request.query_params._dict.copy()
                if "region" not in query_params or not query_params["region"]:
                    query_params["region"] = "us-east-1"
                    logger.info("Region not specified. Defaulting to 'us-east-1'.")

                request.scope["query_string"] = "&".join(
                    f"{key}={value}" for key, value in query_params.items()
                ).encode("utf-8")

                #  check if the query paramater "account_id" is present
                if "account_id" in request.query_params:
                    aws_account_id = request.query_params["account_id"]
                else:
                    # Extract account ID from path patterns like /api/{account_id}/regions
                    path_match = re.match(r'/api/(\d+)/', request.url.path)
                    if path_match:
                        aws_account_id = path_match.group(1)
            logger.info(f"Request path: {request.url.path}, AWS Account ID: {aws_account_id}, Validate ID: {validate_account_id(aws_account_id)}")

            # Get user info from request state (set by CognitoAuthMiddleware)
            user_info = getattr(request.state, 'user', None)

            # Validate AWS account ID if provided
            if aws_account_id is None and not validate_account_id(aws_account_id):
                return JSONResponse(
                    content=format_response(
                        status_code="403",
                        status_message="Forbidden",
                        data={"error": "Invalid AWS account ID or not provided."}
                    ),
                    status_code=403
                )

            # Validate user has access to this account
            if user_info and not validate_user_access_to_account(user_info, aws_account_id):
                logger.warning(f"User {user_info.get('username')} attempted to access account {aws_account_id} without permission")
                return JSONResponse(
                    content=format_response(
                        status_code="403",
                        status_message="Forbidden",
                        data={"error": f"You do not have access to AWS Account ID: {aws_account_id}"}
                    ),
                    status_code=403
                )

            aws_role_name = get_role_name_from_config(aws_account_id)
            if aws_role_name is None:
                return JSONResponse(
                    content=format_response(
                        status_code="403",
                        status_message="Forbidden",
                        data={"error": f"No role name found for AWS Account ID: {aws_account_id}"}
                    ),
                    status_code=403
                )

            role_arn = f"arn:aws:iam::{aws_account_id}:role/{aws_role_name}"
            boto3_session = assume_role(role_arn, session_name="api-session")
            request.state.session = boto3_session
            response = await call_next(request)

            if response.status_code == 200 and "application/json" in response.headers.get("content-type", ""):
                body = b""
                async for chunk in response.body_iterator:
                    body += chunk

                data = json.loads(body.decode("utf-8"))
                formatted_response = format_response(
                    status_code="200",
                    status_message="Success",
                    data=data
                )

                custom_response = JSONResponse(content=formatted_response, status_code=200)

                # Preserve CORS headers
                for header in ["access-control-allow-origin", "access-control-allow-credentials"]:
                    if header in response.headers:
                        custom_response.headers[header] = response.headers[header]

                return custom_response

            return response
        except Exception as e:
            exc_type, exc_value, exc_tb = sys.exc_info()
            tb = traceback.extract_tb(exc_tb)
            for frame in tb:
                print(f"File: {frame.filename}, Line: {frame.lineno}, Function: {frame.name}")
            print(f"Exception: {e}")
            return JSONResponse(
                content=format_response(
                    status_code="500",
                    status_message="Internal Server Errdddor",
                    data={"error": str(e)}
                ),
                status_code=500
            )

def validate_account_id(aws_account_id: str) -> bool:
    for account in config:
        if account["account_id"] == aws_account_id:
            return True
    return False


def get_role_name_from_config(aws_account_id):
    """
    Function to get the AWS role name from the config.
    """
    aws_role_name = None
    with open("config.json", "r") as config_file:
        config = json.load(config_file)
    for account in config:
        if account["account_id"] == aws_account_id:
            aws_role_name = account["role_name"]
    return aws_role_name


def get_account_config_for_user(user_info: Optional[Dict[str, Any]]) -> list:
    """
    Get allowed AWS accounts based on Cognito user groups.
    Maps user groups to AWS accounts.

    Args:
        user_info: User information from Cognito token

    Returns:
        List of allowed account configurations
    """
    if not user_info:
        # If no user info (auth disabled), return all accounts
        return config

    user_groups = user_info.get('groups', [])

    # If user has Admin group, return all accounts
    if 'Admins' in user_groups or 'CloudDashboardAdmins' in user_groups:
        logger.info(f"User {user_info.get('username')} has admin access to all accounts")
        return config

    # Map groups to accounts
    # You can customize this mapping based on your requirements
    allowed_accounts = []
    for account in config:
        account_id = account.get('account_id')

        # Check if user's group matches the account
        # Example: Group "Account-123456789012" gives access to that account
        account_group = f"Account-{account_id}"

        if account_group in user_groups:
            allowed_accounts.append(account)
            continue

        # You can also check for other group patterns
        # Example: "Dev" group gives access to dev accounts
        account_name = account.get('name', '').lower()
        if 'dev' in account_name and 'Developers' in user_groups:
            allowed_accounts.append(account)
        elif 'prod' in account_name and 'Production' in user_groups:
            allowed_accounts.append(account)

    logger.info(f"User {user_info.get('username')} has access to {len(allowed_accounts)} accounts")
    return allowed_accounts


def validate_user_access_to_account(user_info: Optional[Dict[str, Any]], aws_account_id: str) -> bool:
    """
    Validate if the authenticated user has access to the specified AWS account.

    Args:
        user_info: User information from Cognito token
        aws_account_id: AWS account ID to validate

    Returns:
        True if user has access, False otherwise
    """
    allowed_accounts = get_account_config_for_user(user_info)
    return any(account['account_id'] == aws_account_id for account in allowed_accounts)