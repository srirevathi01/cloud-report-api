from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
import json
import sys
import traceback
import os

from middleware.aws_middleware import AWSRoleMiddleware
from middleware.region_middleware import DefaultRegionMiddleware
from controllers.compute_controller import router as compute_router
from controllers.regions_controller import router as regions_router
from utils.response_formatter import format_response

# This is a list of allowed origins for CORS
allowed_origins = os.getenv("ALLOWED_ORIGINS", "http://localhost:5173").split(",")

# Load the config file with error handling and absolute path
config_path = os.path.join(os.path.dirname(__file__), 'config.json')
try:
    with open(config_path, "r") as config_file:
        config = json.load(config_file)
        print(config)
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


# Initialize app
app = FastAPI(
    title="AWS Authentication Services API",
    description="Authentication",
    version="1.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add custom global middleware after CORS
app.add_middleware(GlobalResponseFormatterMiddleware)

# Routers
app.include_router(compute_router)
app.include_router(regions_router, prefix="/api", tags=["regions"])

# Optional: Role and region middlewares (commented for now)
app.add_middleware(AWSRoleMiddleware)
app.add_middleware(DefaultRegionMiddleware)

# Health check
@app.get("/health")
async def health_check():
    return {"status": "healthy"}

# Root endpoint
@app.get("/")
def welcome_message():
    return {"Hello": ["hello", "world"]}
