from fastapi import APIRouter
router = APIRouter()

# Health check
@router.get("/health")
async def health_check():
    return {"status": "healthy"}

# Root endpoint
@router.get("/")
def welcome_message():
    return {"Hello": ["hello", "world"]}