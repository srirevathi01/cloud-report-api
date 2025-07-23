from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from middleware.aws_middleware import AWSRoleMiddleware
from middleware.region_middleware import DefaultRegionMiddleware
import json
import sys
import traceback
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from controllers.compute_controller import router as compute_router
from controllers.regions_controller import router as regions_router
from utils.response_formatter import format_response

# Load the config file with error handling and absolute path
import os
config_path = os.path.join(os.path.dirname(__file__),'config.json')

try:
    with open(config_path, "r") as config_file:
        config = json.load(config_file)
        print(config)
except Exception as e:
    print(f"Error loading config.json from {config_path}: {e}")
    config = []

app = FastAPI(
    title="Cloud Report API",
    description="API to fetch AWS resources",
    version="1.0.2"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Role authentication middlewares
app.add_middleware(AWSRoleMiddleware)

# Default region middleware
app.add_middleware(DefaultRegionMiddleware)

@app.middleware("http")
async def global_response_formatter(request: Request, call_next):
    # Skip middleware for OpenAPI documentation paths
    if request.url.path in ["/docs", "/redoc", "/openapi.json"]:
        return await call_next(request)

    try:
        # Extract AWS account ID from the path if present
        aws_account_id = None
        if "/api/" in request.url.path:  # Check if the request is for an API route
            path_parts = request.url.path.split("/")
            if len(path_parts) > 2:  # Ensure the path has enough parts
                aws_account_id = path_parts[2]  # Extract the account ID from the path

        # Validate AWS account ID if it exists in the request
        if aws_account_id and not validate_account_id(aws_account_id):
            return JSONResponse(
                content=format_response(
                    status_code="403",
                    status_message="Forbidden",
                    data={"error": "Invalid AWS account ID"}
                ),
                status_code=403
            )

        # Process the request and get the response
        response = await call_next(request)

        # Handle JSONResponse or responses with JSON content
        if response.status_code == 200 and response.headers.get("content-type") == "application/json":
            # Read the response body safely
            content = b""
            async for chunk in response.body_iterator:
                content += chunk

            # Decode and parse the response body into JSON
            data = json.loads(content.decode("utf-8"))

            # Format the response
            formatted_response = format_response(
                status_code="200",
                status_message="Success",
                data=data  # Pass the parsed JSON object
            )
            return JSONResponse(content=data, status_code=200)

        # Return the original response if it's not JSON
        return response
    except Exception as e:
        exc_type, exc_value, exc_tb = sys.exc_info()
        tb = traceback.extract_tb(exc_tb)
        for frame in tb:
            print(f"File: {frame.filename}, Line: {frame.lineno}, Function: {frame.name}")
        print(f"Exception: {e}")
        # Handle exceptions and format the error response
        return JSONResponse(
            content=format_response(
                status_code="500",
                status_message="Internal Server Error",
                data={"error": str(e)}
            ),
            status_code=500
        )

# Valiudate AWS account ID against the config file
def validate_account_id(aws_account_id: str) -> bool:
    """
    Validate the AWS account ID against the config file.
    """
    for account in config:
        if account["account_id"] == aws_account_id:
            return True
    return False

@app.get("/")
def welcome_message():
    return {"Hello": ["hello", "world"]}

# Health check endpoint
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy"}

# Include the compute router
app.include_router(compute_router)
app.include_router(regions_router, prefix="/api", tags=["regions"])
