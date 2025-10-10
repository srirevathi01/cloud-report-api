"""
Health Events Category API Router
Handles listing and describing AWS health-related events and services
(AWS Health Dashboard, Personal Health Dashboard, Service Health)
"""

from fastapi import APIRouter, Query, HTTPException, Request
from pydantic import BaseModel, Field, validator
from typing import List, Dict, Any, Optional
from botocore.exceptions import BotoCoreError, ClientError
import logging

router = APIRouter()
logger = logging.getLogger(__name__)

# ----------------------------
# Constants
# ----------------------------
SUPPORTED_SERVICES = [
    "aws-health",
    "personal-health-dashboard",
    "service-health"
]


class ResourceIds(BaseModel):
    """Request model for describing specific health events"""
    ids: List[str] = Field(..., min_items=1, max_items=50, description="List of event or entity ARNs/IDs")
    region: str = Field(default="us-east-1", description="AWS region")

    @validator('ids')
    def validate_ids(cls, v):
        if not all(isinstance(_id, str) and _id.strip() for _id in v):
            raise ValueError("All IDs must be non-empty strings")
        return v


def get_aws_client(session, service: str, region: str):
    """Create AWS client with error handling"""
    try:
        return session.client(service, region_name=region)
    except Exception as e:
        logger.error(f"Failed to create {service} client: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to create AWS client: {str(e)}")


def handle_aws_error(e: Exception, context: str = ""):
    """Centralized AWS error handling with appropriate HTTP status codes."""
    if isinstance(e, ClientError):
        error_code = e.response.get("Error", {}).get("Code", "Unknown")
        error_msg = e.response.get("Error", {}).get("Message", str(e))
        logger.error(f"AWS Error in {context}: {error_code} - {error_msg}")

        status_code = 500
        if error_code in ["AccessDenied", "UnauthorizedOperation"]:
            status_code = 403
        elif error_code in ["InvalidParameterValue", "ValidationError", "InvalidParameterCombination"]:
            status_code = 400
        elif error_code in ["ResourceNotFoundException"]:
            status_code = 404

        raise HTTPException(status_code=status_code, detail=f"{error_code}: {error_msg}")
    else:
        logger.error(f"Unexpected error in {context}: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# ----------------------------
# API ENDPOINTS
# ----------------------------

@router.get("/health-events", summary="List all health-related services in the category")
def list_health_services(
    request: Request,
    account_id: Optional[str] = Query(None, description="AWS Account ID"),
    region: Optional[str] = Query(None, description="AWS Region")
):
    """
    Step 1: List all available health-related services in the category.
    """
    try:
        _ = request.state.session  # Validate session exists
        return {
            "category": "health-events",
            "services": SUPPORTED_SERVICES,
            "service_descriptions": {
                "aws-health": "AWS Health events affecting AWS resources in your account",
                "personal-health-dashboard": "Personalized view of AWS health events specific to your account",
                "service-health": "General AWS Service Health across all regions"
            },
            "account_id": account_id,
            "region": region or "Not specified"
        }
    except AttributeError:
        raise HTTPException(status_code=401, detail="Authentication required")


@router.get("/health-events/{service_name}", summary="List all events for a health-related service")
def list_health_resources(
    service_name: str,
    request: Request,
    account_id: Optional[str] = Query(None, description="AWS Account ID"),
    region: str = Query(default="us-east-1", description="AWS Region")
):
    """
    Step 2: List all health events or affected entities for a specific service.
    """
    service_name = service_name.lower()
    if service_name not in SUPPORTED_SERVICES:
        raise HTTPException(status_code=400, detail=f"Service '{service_name}' not supported. Supported: {SUPPORTED_SERVICES}")

    try:
        session = request.state.session

        if service_name == "aws-health":
            client = get_aws_client(session, "health", region)
            events = client.describe_events().get("events", [])
            resources = events

        elif service_name == "personal-health-dashboard":
            client = get_aws_client(session, "health", region)
            events = client.describe_events(filter={"eventStatusCodes": ["open", "upcoming", "closed"]}).get("events", [])
            resources = events

        elif service_name == "service-health":
            client = get_aws_client(session, "health", region)
            events = client.describe_events(filter={"eventTypeCategories": ["issue", "accountNotification"]}).get("events", [])
            resources = events

        return {
            "category": "health-events",
            "service": service_name,
            "account_id": account_id,
            "region": region,
            "total_resources": len(resources),
            "resources": resources
        }

    except (BotoCoreError, ClientError) as e:
        handle_aws_error(e, f"list_health_resources/{service_name}")
    except AttributeError:
        raise HTTPException(status_code=401, detail="Authentication required")


@router.post("/health-events/{service_name}", summary="Get detailed info for specific health events")
def describe_specific_health_resources(
    service_name: str,
    request: Request,
    resource_ids: ResourceIds,
    account_id: Optional[str] = Query(None, description="AWS Account ID")
):
    """
    Step 3: Get detailed information for specific health events or affected entities.
    """
    service_name = service_name.lower()
    if service_name not in SUPPORTED_SERVICES:
        raise HTTPException(status_code=400, detail=f"Service '{service_name}' not supported. Supported: {SUPPORTED_SERVICES}")

    try:
        session = request.state.session
        details = []

        if service_name == "aws-health":
            client = get_aws_client(session, "health", resource_ids.region)
            response = client.describe_event_details(eventArns=resource_ids.ids)
            details = response.get("successfulSet", [])

        elif service_name == "personal-health-dashboard":
            client = get_aws_client(session, "health", resource_ids.region)
            response = client.describe_affected_entities(filter={"eventArns": resource_ids.ids})
            details = response.get("entities", [])

        elif service_name == "service-health":
            client = get_aws_client(session, "health", resource_ids.region)
            response = client.describe_event_details(eventArns=resource_ids.ids)
            details = response.get("successfulSet", [])

        return {
            "category": "health-events",
            "service": service_name,
            "account_id": account_id,
            "region": resource_ids.region,
            "total_resources": len(details),
            "resources": details
        }

    except (BotoCoreError, ClientError) as e:
        handle_aws_error(e, f"describe_specific_health_resources/{service_name}")
    except AttributeError:
        raise HTTPException(status_code=401, detail="Authentication required")
