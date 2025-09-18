from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import os

# Import custom middleware
from middleware.aws_middleware import AWSMiddleware


# Import routers
from controllers.healthcheck_controller import router as healthcheck_router
from controllers.compute_controller import router as compute_router
from controllers.regions_controller import router as regions_router
from controllers.database_controller import router as database_router

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
app.include_router(regions_router, prefix="/api", tags=["regions"])
app.include_router(database_router, prefix="/api", tags=["databases"])

# Add custom AWS middleware after CORS
app.add_middleware(AWSMiddleware)
