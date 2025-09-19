import json
import sys
import traceback
import os
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
            if request.url.path in ["/docs", "/favicon.ico", "/openapi.json"]:
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
            logger.info(f"Request path: {request.url.path}, AWS Account ID: {aws_account_id}, Validate ID: {validate_account_id(aws_account_id)}")

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
            credentials = assume_role(role_arn, session_name="api-session")
            request.state.aws_credentials = credentials
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