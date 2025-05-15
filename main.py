from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from middleware.aws_middleware import AWSRoleMiddleware
from middleware.region_middleware import DefaultRegionMiddleware

app = FastAPI(
    title="AWS Authentication Services API",
    description="Authentication",
    version="1.0.0"
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

# Health check endpoint
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy"}
