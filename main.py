from typing import Union
import json
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from controllers.compute import router as compute_router
from utils.response_formatter import format_response

app = FastAPI()

@app.middleware("http")
async def global_response_formatter(request: Request, call_next):
    try:
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
            return JSONResponse(content=formatted_response, status_code=200)

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

@app.get("/")
def welcome_message():
    return {"Hello": ["hello", "world"]}

# Include the compute router
app.include_router(compute_router)