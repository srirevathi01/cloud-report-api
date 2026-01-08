from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
import os
import logging
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Verify critical environment variables are loaded
logger = logging.getLogger(__name__)

# Import custom middleware
from middleware.aws_middleware import AWSMiddleware
from middleware.cognito_auth import CognitoAuthMiddleware

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# Import routers
from controllers.healthcheck_controller import router as healthcheck_router
from controllers.auth_controller import router as auth_router
from controllers.compute_controller import router as compute_router
from controllers.monitoring_controller import router as monitoring_router
from controllers.regions_controller import router as regions_router
from controllers.database_controller import router as database_router
from controllers.network_controller import router as network_router
from controllers.storage_controller import router as storage_router
from controllers.security_controller import router as security_router
from controllers.billing_controller import router as billing_router


# This is a list of allowed origins for CORS
allowed_origins = os.getenv("ALLOWED_ORIGINS", "https://d1fd4y10eleeus.cloudfront.net").split(",")

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
app.include_router(auth_router, prefix="/api", tags=["authentication"])
app.include_router(compute_router, prefix="/api", tags=["compute"])
app.include_router(monitoring_router, prefix="/api", tags=["monitoring"])
app.include_router(regions_router, prefix="/api", tags=["regions"])
app.include_router(network_router, prefix="/api", tags=["network"])
app.include_router(database_router, prefix="/api", tags=["database"])
app.include_router(storage_router, prefix="/api", tags=["storage"])
app.include_router(security_router, prefix="/api", tags=["security"])
app.include_router(billing_router, prefix="/api", tags=["billing"])



# Add Cognito authentication middleware
# This must be added BEFORE the AWS middleware so user info is available
app.add_middleware(
    CognitoAuthMiddleware,
    exclude_paths=['/docs', '/redoc', '/openapi.json', '/health', '/favicon', '/api/auth']
)

# Add custom AWS middleware after authentication
app.add_middleware(AWSMiddleware)

# Log configuration status
cognito_configured = all([
    os.getenv('COGNITO_USER_POOL_ID'),
    os.getenv('COGNITO_CLIENT_ID'),
    os.getenv('COGNITO_DOMAIN')
])
logger.info(f"FastAPI application initialized with Cognito authentication (configured: {cognito_configured})")
if cognito_configured:
    logger.info(f"Cognito User Pool: {os.getenv('COGNITO_USER_POOL_ID')}")
    logger.info(f"Cognito Domain: {os.getenv('COGNITO_DOMAIN')}")
    logger.info(f"Client Secret present: {bool(os.getenv('COGNITO_CLIENT_SECRET'))}")

# Add dummy favicon route (to stop 403 in logs)
@app.get("/favicon")
async def favicon():
    return Response(content=b"", media_type="image/x-icon")