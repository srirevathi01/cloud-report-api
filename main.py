from typing import Union
import json
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from controllers.compute import router as compute_router
from controllers.regions import router as regions_router
from utils.response_formatter import format_response

app = FastAPI()

# Load the config file
with open("config.json", "r") as config_file:
    config = json.load(config_file)

# Load the config file
with open("config.json", "r") as config_file:
    config = json.load(config_file)

@app.middleware("http")
async def global_response_formatter(request: Request, call_next):
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
        # Handle exceptions and format the error response
        return JSONResponse(
            content=format_response(
                status_code="500",
                status_message="Internal Server Error",
                data={"error": str(e)}
            ),
            status_code=500
        )

def validate_account_id(aws_account_id: str) -> bool:
    """
    Validate the AWS account ID against the config file.
    """
    for account in config["accounts"]:
        if account["account_id"] == aws_account_id:
            return True
    return False

@app.get("/")
def welcome_message():
    return {"Hello": ["hello", "world"]}

# Include the compute router
app.include_router(compute_router)
app.include_router(regions_router, prefix="/api", tags=["regions"])
