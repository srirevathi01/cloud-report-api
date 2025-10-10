from fastapi import APIRouter, Query, HTTPException, Request
from pydantic import BaseModel, Field, validator
from typing import List, Optional
from botocore.exceptions import BotoCoreError, ClientError
import logging
import requests

router = APIRouter()
logger = logging.getLogger(__name__)

SUPPORTED_SERVICES = [
    "aws-health",
    "personal-health-dashboard",
    "service-health"
]

class ResourceIds(BaseModel):
    ids: List[str] = Field(..., min_items=1, max_items=50)
    region: str = Field(default="us-east-1")

    @validator("ids")
    def validate_ids(cls, v):
        if not all(isinstance(_id, str) and _id.strip() for _id in v):
            raise ValueError("All IDs must be non-empty strings")
        return v

def get_aws_client(session, service: str, region: str):
    try:
        return session.client(service, region_name=region)
    except Exception as e:
        logger.error(f"Failed to create {service} client: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to create AWS client: {str(e)}")

def handle_aws_error(e: Exception, context: str = ""):
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

def fallback_service_health():
    """Return public AWS service status"""
    try:
        data = requests.get("https://status.aws.amazon.com/data.json", timeout=5).json()
        services = []
        for s in data.get("services", []):
            services.append({
                "service": s.get("name"),
                "status": s.get("status"),
                "last_updated": s.get("last_updated")
            })
        return services if services else [{"message": "Fallback service-health data unavailable"}]
    except Exception:
        return [{"message": "Fallback service-health data unavailable"}]

def fallback_personal_health_dashboard():
    """Return placeholder data for personal-health-dashboard"""
    common_services = ["EC2", "S3", "RDS", "Lambda", "VPC"]
    return [{"service": s, "status": "Unknown", "message": "Requires AWS subscription"} for s in common_services]

# --------- API Endpoints ---------

@router.get("/health-events")
def list_health_services(request: Request, account_id: Optional[str] = None, region: Optional[str] = None):
    try:
        _ = request.state.session
        return {
            "statusCode": 200,
            "statusMessage": "Success",
            "data": {
                "category": "health-events",
                "services": SUPPORTED_SERVICES,
                "account_id": account_id,
                "region": region or "Not specified"
            }
        }
    except AttributeError:
        raise HTTPException(status_code=401, detail="Authentication required")

@router.get("/health-events/{service_name}")
def list_health_resources(service_name: str, request: Request, account_id: Optional[str] = None, region: str = "us-east-1"):
    service_name = service_name.lower()
    if service_name not in SUPPORTED_SERVICES:
        raise HTTPException(status_code=400, detail=f"Service '{service_name}' not supported")
    try:
        session = request.state.session
        health_region = "us-east-1"
        resources = []

        if service_name == "aws-health":
            client = get_aws_client(session, "health", health_region)
            try:
                resources = client.describe_events().get("events", [])
            except ClientError as e:
                error_code = e.response.get("Error", {}).get("Code")
                if error_code == "SubscriptionRequiredException":
                    resources = [{"message": "SubscriptionRequired: Cannot access detailed info"}]

        elif service_name == "personal-health-dashboard":
            client = get_aws_client(session, "health", health_region)
            try:
                resources = client.describe_events(filter={"eventStatusCodes": ["open", "upcoming", "closed"]}).get("events", [])
            except ClientError:
                resources = fallback_personal_health_dashboard()

        elif service_name == "service-health":
            try:
                client = get_aws_client(session, "health", health_region)
                resources = client.describe_events(filter={"eventTypeCategories": ["issue", "accountNotification"]}).get("events", [])
            except ClientError:
                resources = fallback_service_health()

        return {
            "statusCode": 200,
            "statusMessage": "Success",
            "data": {
                "category": "health-events",
                "service": service_name,
                "account_id": account_id,
                "region": region,
                "total_resources": len(resources),
                "resources": resources
            }
        }
    except AttributeError:
        raise HTTPException(status_code=401, detail="Authentication required")

@router.post("/health-events/{service_name}")
def describe_specific_health_resources(service_name: str, request: Request, resource_ids: ResourceIds, account_id: Optional[str] = None):
    service_name = service_name.lower()
    if service_name not in SUPPORTED_SERVICES:
        raise HTTPException(status_code=400, detail=f"Service '{service_name}' not supported")
    try:
        session = request.state.session
        details = []
        health_region = "us-east-1"
        client = get_aws_client(session, "health", health_region)
        try:
            if service_name in ["aws-health", "service-health"]:
                response = client.describe_event_details(eventArns=resource_ids.ids)
                details = response.get("successfulSet", [])
            elif service_name == "personal-health-dashboard":
                response = client.describe_affected_entities(filter={"eventArns": resource_ids.ids})
                details = response.get("entities", [])
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code")
            if error_code == "SubscriptionRequiredException":
                details = [{"message": "SubscriptionRequired: Cannot access detailed info"}]
            else:
                handle_aws_error(e, f"describe_specific_health_resources/{service_name}")

        return {
            "statusCode": 200,
            "statusMessage": "Success",
            "data": {
                "category": "health-events",
                "service": service_name,
                "account_id": account_id,
                "region": resource_ids.region,
                "total_resources": len(details),
                "resources": details
            }
        }
    except AttributeError:
        raise HTTPException(status_code=401, detail="Authentication required")
