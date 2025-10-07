"""
Logs Category API Router
Handles listing and describing AWS logging-related resources
(CloudWatch Logs, VPC Flow Logs, CloudTrail, S3 Access Logs, ELB Access Logs)
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
    "cloudwatch-logs",
    "vpc-flow-logs",
    "cloudtrail-logs",
    "s3-access-logs",
    "elb-access-logs"
]


class ResourceIds(BaseModel):
    """Request model for describing specific resources"""
    ids: List[str] = Field(..., min_items=1, max_items=50, description="List of resource IDs/names")
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

@router.get("/logs", summary="List all logging services in the category")
def list_logging_services(
    request: Request,
    account_id: Optional[str] = Query(None, description="AWS Account ID"),
    region: Optional[str] = Query(None, description="AWS Region")
):
    """
    Step 1: List all available logging services in the category.
    """
    try:
        _ = request.state.session  # Validate session exists
        return {
            "category": "logs",
            "services": SUPPORTED_SERVICES,
            "service_descriptions": {
                "cloudwatch-logs": "Amazon CloudWatch Logs groups and streams",
                "vpc-flow-logs": "VPC Flow Logs for network traffic",
                "cloudtrail-logs": "AWS CloudTrail trails and events",
                "s3-access-logs": "S3 Bucket access logs",
                "elb-access-logs": "Classic ELB access logs"
            },
            "account_id": account_id,
            "region": region or "Not specified"
        }
    except AttributeError:
        raise HTTPException(status_code=401, detail="Authentication required")


@router.get("/logs/{service_name}", summary="List all resources for a logging service")
def list_logging_resources(
    service_name: str,
    request: Request,
    account_id: Optional[str] = Query(None, description="AWS Account ID"),
    region: str = Query(default="us-east-1", description="AWS Region"),
    vpc_id: Optional[str] = Query(None, description="Optional VPC ID for flow logs")
):
    """
    Step 2: List all resources for a specific logging service.
    """
    service_name = service_name.lower()
    if service_name not in SUPPORTED_SERVICES:
        raise HTTPException(status_code=400, detail=f"Service '{service_name}' not supported. Supported: {SUPPORTED_SERVICES}")

    try:
        session = request.state.session

        if service_name == "cloudwatch-logs":
            client = get_aws_client(session, "logs", region)
            groups = client.describe_log_groups().get("logGroups", [])
            resources = groups

        elif service_name == "vpc-flow-logs":
            client = get_aws_client(session, "ec2", region)
            filters = [{"Name": "resource-id", "Values": [vpc_id]}] if vpc_id else []
            flow_logs = client.describe_flow_logs(Filters=filters).get("FlowLogs", [])
            resources = flow_logs

        elif service_name == "cloudtrail-logs":
            client = get_aws_client(session, "cloudtrail", region)
            trails = client.describe_trails().get("trailList", [])
            resources = trails

        elif service_name == "s3-access-logs":
            client = get_aws_client(session, "s3", region)
            buckets = client.list_buckets().get("Buckets", [])
            resources = []
            for b in buckets:
                try:
                    logging_info = client.get_bucket_logging(Bucket=b["Name"]).get("LoggingEnabled", {})
                    versioning = client.get_bucket_versioning(Bucket=b["Name"]).get("Status", "None")
                    bucket_region = client.get_bucket_location(Bucket=b["Name"]).get("LocationConstraint") or "us-east-1"
                    resources.append({
                        "BucketName": b["Name"],
                        "Logging": logging_info,
                        "Versioning": versioning,
                        "Region": bucket_region
                    })
                except Exception:
                    continue

        elif service_name == "elb-access-logs":
            client = get_aws_client(session, "elb", region)
            lbs = client.describe_load_balancers().get("LoadBalancerDescriptions", [])
            resources = [
                {
                    "LoadBalancerName": lb["LoadBalancerName"],
                    "Scheme": lb["Scheme"],
                    "DNSName": lb["DNSName"]
                }
                for lb in lbs
            ]

        return {
            "category": "logs",
            "service": service_name,
            "account_id": account_id,
            "region": region,
            "total_resources": len(resources),
            "resources": resources
        }

    except (BotoCoreError, ClientError) as e:
        handle_aws_error(e, f"list_logging_resources/{service_name}")
    except AttributeError:
        raise HTTPException(status_code=401, detail="Authentication required")


@router.post("/logs/{service_name}", summary="Get detailed info for specific logging resources")
def describe_specific_logging_resources(
    service_name: str,
    request: Request,
    resource_ids: ResourceIds,
    account_id: Optional[str] = Query(None, description="AWS Account ID")
):
    """
    Step 3: Get detailed information for specific logging resources.
    """
    service_name = service_name.lower()
    if service_name not in SUPPORTED_SERVICES:
        raise HTTPException(status_code=400, detail=f"Service '{service_name}' not supported. Supported: {SUPPORTED_SERVICES}")

    try:
        session = request.state.session
        details = []

        if service_name == "cloudwatch-logs":
            client = get_aws_client(session, "logs", resource_ids.region)
            for lg_name in resource_ids.ids:
                try:
                    lg = client.describe_log_groups(logGroupNamePrefix=lg_name)["logGroups"]
                    details.extend(lg)
                except Exception:
                    continue

        elif service_name == "vpc-flow-logs":
            client = get_aws_client(session, "ec2", resource_ids.region)
            flow_logs = client.describe_flow_logs(Filters=[{"Name": "resource-id", "Values": resource_ids.ids}]).get("FlowLogs", [])
            details.extend(flow_logs)

        elif service_name == "cloudtrail-logs":
            client = get_aws_client(session, "cloudtrail", resource_ids.region)
            trails = client.describe_trails().get("trailList", [])
            for t in trails:
                if t["Name"] in resource_ids.ids:
                    details.append(t)

        elif service_name == "s3-access-logs":
            client = get_aws_client(session, "s3", resource_ids.region)
            for b_name in resource_ids.ids:
                try:
                    logging_info = client.get_bucket_logging(Bucket=b_name).get("LoggingEnabled", {})
                    versioning = client.get_bucket_versioning(Bucket=b_name).get("Status", "None")
                    bucket_region = client.get_bucket_location(Bucket=b_name).get("LocationConstraint") or "us-east-1"
                    if logging_info:
                        details.append({
                            "BucketName": b_name,
                            "Logging": logging_info,
                            "Versioning": versioning,
                            "Region": bucket_region
                        })
                except Exception:
                    continue

        elif service_name == "elb-access-logs":
            client = get_aws_client(session, "elb", resource_ids.region)
            lbs = client.describe_load_balancers()["LoadBalancerDescriptions"]
            for lb in lbs:
                if lb["LoadBalancerName"] in resource_ids.ids:
                    details.append({
                        "LoadBalancerName": lb["LoadBalancerName"],
                        "Scheme": lb["Scheme"],
                        "DNSName": lb["DNSName"],
                        "AccessLog": lb.get("AccessLog", {})
                    })

        return {
            "category": "logs",
            "service": service_name,
            "account_id": account_id,
            "region": resource_ids.region,
            "total_resources": len(details),
            "resources": details
        }

    except (BotoCoreError, ClientError) as e:
        handle_aws_error(e, f"describe_specific_logging_resources/{service_name}")
    except AttributeError:
        raise HTTPException(status_code=401, detail="Authentication required")
