from fastapi import APIRouter

router = APIRouter()

@router.get("/compute")
def list_compute_services():
    return {
        "EC2",
        "Lambda",
        "ECS",
        "EKS",
        "Lightsail",
        "Batch",
        "Outposts"
    }