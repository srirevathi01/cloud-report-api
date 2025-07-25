import json
import sys
import traceback
import os
from utils.response_formatter import format_response
from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

# Load the config file with error handling and absolute path
config_path = os.path.join(os.path.dirname(__file__), '..', 'config.json')
try:
    with open(config_path, "r") as config_file:
        config = json.load(config_file)
except Exception as e:
    print(f"Error loading config.json from {config_path}: {e}")
    config = []


def validate_account_id(aws_account_id: str) -> bool:
    for account in config:
        if account["account_id"] == aws_account_id:
            return True
    return False


# Define class-based middleware
class GlobalResponseFormatterMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        try:
            aws_account_id = None
            if "/api/" in request.url.path:
                path_parts = request.url.path.split("/")
                print(f"Path parts: {path_parts}")
                if len(path_parts) > 2:
                    aws_account_id = path_parts[2]
            
            if aws_account_id and not validate_account_id(aws_account_id):
                return JSONResponse(
                    content=format_response(
                        status_code="403",
                        status_message="Forbidden",
                        data={"error": "Invalid AWS account ID"}
                    ),
                    status_code=403
                )

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
                    status_message="Internal Server Error",
                    data={"error": str(e)}
                ),
                status_code=500
            )
