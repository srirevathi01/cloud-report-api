from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
import os

# Import custom middleware
from middleware.aws_middleware import AWSMiddleware


# Import routers
from controllers.healthcheck_controller import router as healthcheck_router
from controllers.compute_controller import router as compute_router
from controllers.computev3_controller import router as compute_router_v3
from controllers.regions_controller import router as regions_router

# This is a list of allowed origins for CORS
allowed_origins = os.getenv("ALLOWED_ORIGINS", "http://localhost:5173").split(",")

# Initialize app
app = FastAPI(
    title="Cloud Report API",
    description="API to fetch cloud resources and reports",
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

# Routers
app.include_router(healthcheck_router, tags=["healthcheck"])
app.include_router(compute_router, prefix="/api", tags=["compute"])
app.include_router(compute_router_v3, prefix="/api", tags=["compute-v3"])
app.include_router(regions_router, prefix="/api", tags=["regions"])

# Add custom AWS middleware after CORS
app.add_middleware(AWSMiddleware)

# Add dummy favicon route (to stop 403 in logs)
@app.get("/favicon.ico")
async def favicon():
    return Response(content=b"", media_type="image/x-icon")