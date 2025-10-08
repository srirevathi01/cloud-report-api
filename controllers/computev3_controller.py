from fastapi import APIRouter, Request, HTTPException, Query
from pydantic import BaseModel, Field, validator
from typing import List, Dict, Any, Optional
import boto3
from botocore.exceptions import ClientError
import logging

router = APIRouter()
logger = logging.getLogger(__name__)

# Constants
SUPPORTED_SERVICES = ["ec2", "lambda", "ecs"]
VALID_REGIONS = [
    "us-east-1", "us-east-2", "us-west-1", "us-west-2",
    "eu-west-1", "eu-central-1", "ap-south-1", "ap-southeast-1"
]

# --- Request/Response Models ---
class ResourceRequest(BaseModel):
    ids: List[str] = Field(..., min_items=1, max_items=50, description="List of resource IDs")
    region: str = Field(default="us-east-1", description="AWS region")

    @validator('region')
    def validate_region(cls, v):
        if v not in VALID_REGIONS:
            raise ValueError(f"Region must be one of {VALID_REGIONS}")
        return v

    @validator('ids')
    def validate_ids(cls, v):
        if not all(isinstance(id, str) and id.strip() for id in v):
            raise ValueError("All IDs must be non-empty strings")
        return v


# --- Helper Functions ---
def get_aws_client(session, service: str, region: str):
    """Create and return an AWS client with error handling."""
    try:
        return session.client(service, region_name=region)
    except Exception as e:
        logger.error(f"Failed to create {service} client: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to create AWS client: {str(e)}")


def handle_aws_error(e: ClientError, context: str = ""):
    """Centralized AWS error handling."""
    error_code = e.response.get('Error', {}).get('Code', 'Unknown')
    error_msg = e.response.get('Error', {}).get('Message', str(e))
    logger.error(f"AWS Error in {context}: {error_code} - {error_msg}")
    
    status_code = 500
    if error_code in ['AccessDenied', 'UnauthorizedOperation']:
        status_code = 403
    elif error_code in ['InvalidParameterValue', 'ValidationError']:
        status_code = 400
    elif error_code in ['ResourceNotFoundException', 'InvalidInstanceID.NotFound']:
        status_code = 404
    
    raise HTTPException(status_code=status_code, detail=f"{error_code}: {error_msg}")


# --- EC2 Functions ---
def list_ec2_instances(client) -> List[Dict[str, Any]]:
    """List all EC2 instances with pagination support."""
    resources = []
    paginator = client.get_paginator('describe_instances')
    
    for page in paginator.paginate():
        for reservation in page.get("Reservations", []):
            for instance in reservation.get("Instances", []):
                resources.append({
                    "InstanceId": instance["InstanceId"],
                    "State": instance["State"]["Name"],
                    "Type": instance["InstanceType"],
                    "Family": instance["InstanceType"].split('.')[0],
                    "LaunchTime": instance["LaunchTime"].isoformat(),
                    "AvailabilityZone": instance.get("Placement", {}).get("AvailabilityZone"),
                    "PrivateIpAddress": instance.get("PrivateIpAddress"),
                    "PublicIpAddress": instance.get("PublicIpAddress")
                })
    
    return resources


def describe_ec2_instances(client, instance_ids: List[str]) -> List[Dict[str, Any]]:
    """Describe specific EC2 instances."""
    details = []
    response = client.describe_instances(InstanceIds=instance_ids)
    
    for reservation in response.get("Reservations", []):
        for instance in reservation.get("Instances", []):
            details.append({
                "InstanceId": instance["InstanceId"],
                "State": instance["State"]["Name"],
                "Type": instance["InstanceType"],
                "Family": instance["InstanceType"].split('.')[0],
                "LaunchTime": instance["LaunchTime"].isoformat(),
                "AvailabilityZone": instance.get("Placement", {}).get("AvailabilityZone"),
                "PrivateIpAddress": instance.get("PrivateIpAddress"),
                "PublicIpAddress": instance.get("PublicIpAddress"),
                "VpcId": instance.get("VpcId"),
                "SubnetId": instance.get("SubnetId"),
                "SecurityGroups": [sg["GroupId"] for sg in instance.get("SecurityGroups", [])],
                "Tags": {tag["Key"]: tag["Value"] for tag in instance.get("Tags", [])}
            })
    
    return details


# --- Lambda Functions ---
def list_lambda_functions(client) -> List[Dict[str, Any]]:
    """List all Lambda functions with pagination."""
    resources = []
    paginator = client.get_paginator("list_functions")
    
    for page in paginator.paginate():
        for fn in page.get("Functions", []):
            resources.append({
                "FunctionName": fn["FunctionName"],
                "Runtime": fn.get("Runtime"),
                "MemorySize": fn.get("MemorySize"),
                "Timeout": fn.get("Timeout"),
                "LastModified": fn.get("LastModified"),
                "State": fn.get("State", "Unknown"),
                "CodeSize": fn.get("CodeSize"),
                "Handler": fn.get("Handler")
            })
    
    return resources


def describe_lambda_functions(client, function_names: List[str]) -> List[Dict[str, Any]]:
    """Describe specific Lambda functions."""
    details = []
    
    for fn_name in function_names:
        try:
            response = client.get_function(FunctionName=fn_name)
            config = response.get("Configuration", {})
            details.append({
                "FunctionName": config.get("FunctionName"),
                "FunctionArn": config.get("FunctionArn"),
                "Runtime": config.get("Runtime"),
                "Role": config.get("Role"),
                "Handler": config.get("Handler"),
                "MemorySize": config.get("MemorySize"),
                "Timeout": config.get("Timeout"),
                "LastModified": config.get("LastModified"),
                "State": config.get("State", "Unknown"),
                "CodeSize": config.get("CodeSize"),
                "Environment": config.get("Environment", {}).get("Variables", {}),
                "Layers": [layer["Arn"] for layer in config.get("Layers", [])]
            })
        except ClientError as e:
            if e.response.get('Error', {}).get('Code') == 'ResourceNotFoundException':
                logger.warning(f"Lambda function not found: {fn_name}")
                details.append({"FunctionName": fn_name, "Error": "Not found"})
            else:
                raise
    
    return details


# --- ECS Functions ---
def list_ecs_clusters(client) -> List[str]:
    """List all ECS cluster names."""
    resources = []
    paginator = client.get_paginator('list_clusters')
    
    for page in paginator.paginate():
        for arn in page.get("clusterArns", []):
            cluster_name = arn.split("/")[-1]
            resources.append(cluster_name)
    
    return resources


def describe_ecs_clusters(client, cluster_names: List[str]) -> List[Dict[str, Any]]:
    """Describe specific ECS clusters with their services and tasks."""
    details = []
    
    # Describe clusters in batches (max 100 per call)
    for i in range(0, len(cluster_names), 100):
        batch = cluster_names[i:i+100]
        cluster_resp = client.describe_clusters(clusters=batch)
        
        for cluster in cluster_resp.get("clusters", []):
            cluster_name = cluster["clusterName"]
            cluster_info = {
                "ClusterName": cluster_name,
                "ClusterArn": cluster.get("clusterArn"),
                "Status": cluster["status"],
                "RunningTasksCount": cluster.get("runningTasksCount", 0),
                "PendingTasksCount": cluster.get("pendingTasksCount", 0),
                "ActiveServicesCount": cluster.get("activeServicesCount", 0),
                "RegisteredContainerInstancesCount": cluster.get("registeredContainerInstancesCount", 0),
                "Services": []
            }

            # Get services in this cluster
            try:
                service_arns = []
                service_paginator = client.get_paginator('list_services')
                for page in service_paginator.paginate(cluster=cluster_name):
                    service_arns.extend(page.get("serviceArns", []))
                
                if service_arns:
                    # Describe services in batches (max 10 per call)
                    for j in range(0, len(service_arns), 10):
                        service_batch = service_arns[j:j+10]
                        service_desc = client.describe_services(
                            cluster=cluster_name,
                            services=service_batch
                        )
                        
                        for service in service_desc.get("services", []):
                            service_info = {
                                "ServiceName": service["serviceName"],
                                "ServiceArn": service.get("serviceArn"),
                                "Status": service["status"],
                                "DesiredCount": service["desiredCount"],
                                "RunningCount": service["runningCount"],
                                "PendingCount": service.get("pendingCount", 0),
                                "LaunchType": service.get("launchType", "UNKNOWN"),
                                "TaskDefinition": service.get("taskDefinition"),
                                "Tasks": []
                            }

                            # Get tasks for this service
                            try:
                                task_arns = []
                                task_paginator = client.get_paginator('list_tasks')
                                for task_page in task_paginator.paginate(
                                    cluster=cluster_name,
                                    serviceName=service["serviceName"]
                                ):
                                    task_arns.extend(task_page.get("taskArns", []))
                                
                                if task_arns:
                                    # Describe tasks in batches (max 100 per call)
                                    for k in range(0, len(task_arns), 100):
                                        task_batch = task_arns[k:k+100]
                                        task_desc = client.describe_tasks(
                                            cluster=cluster_name,
                                            tasks=task_batch
                                        )
                                        
                                        for task in task_desc.get("tasks", []):
                                            service_info["Tasks"].append({
                                                "TaskArn": task["taskArn"],
                                                "TaskDefinitionArn": task.get("taskDefinitionArn"),
                                                "LaunchType": task.get("launchType", "UNKNOWN"),
                                                "LastStatus": task["lastStatus"],
                                                "DesiredStatus": task["desiredStatus"],
                                                "CreatedAt": task.get("createdAt").isoformat() if task.get("createdAt") else None
                                            })
                            except ClientError as e:
                                logger.warning(f"Error fetching tasks for service {service['serviceName']}: {str(e)}")
                            
                            cluster_info["Services"].append(service_info)
            except ClientError as e:
                logger.warning(f"Error fetching services for cluster {cluster_name}: {str(e)}")
            
            details.append(cluster_info)
    
    return details


# --- API Endpoints ---
@router.get("/computev3", summary="List supported compute services")
def list_compute_services(request: Request, account_id: str = Query(..., description="AWS account ID"),region: str = Query("us-east-1", description="AWS region")):
    """List all compute services supported by the API."""
    try:
        _ = request.state.session  # Validate session exists
        return {
            "compute_services": SUPPORTED_SERVICES,
            "version": "3.0",
            "supported_regions": VALID_REGIONS
        }
    except AttributeError:
        raise HTTPException(status_code=401, detail="Authentication required")
    except Exception as e:
        logger.error(f"Error listing compute services: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/computev3/{service_name}/list", summary="List resources for a compute service")
def list_service_resources(
    service_name: str,
    request: Request,
    account_id: str = Query(..., description="AWS account ID"),
    region: str = Query(default="us-east-1", description="AWS region")
):
    """List all resources under a specific compute service."""
    service_name = service_name.lower()
    
    if service_name not in SUPPORTED_SERVICES:
        raise HTTPException(
            status_code=400,
            detail=f"Service '{service_name}' not supported. Supported services: {SUPPORTED_SERVICES}"
        )
    
    if region not in VALID_REGIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid region. Supported regions: {VALID_REGIONS}"
        )
    
    try:
        creds = request.state.session
        resources = []

        if service_name == "ec2":
            client = get_aws_client(creds, "ec2", region)
            resources = list_ec2_instances(client)

        elif service_name == "lambda":
            client = get_aws_client(creds, "lambda", region)
            resources = list_lambda_functions(client)

        elif service_name == "ecs":
            client = get_aws_client(creds, "ecs", region)
            resources = list_ecs_clusters(client)

        return {
            "service_name": service_name,
            "region": region,
            "count": len(resources),
            "resources": resources
        }

    except ClientError as e:
        handle_aws_error(e, f"list_service_resources/{service_name}")
    except AttributeError:
        raise HTTPException(status_code=401, detail="Authentication required")
    except Exception as e:
        logger.error(f"Unexpected error in list_service_resources: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/computev3/{service_name}", summary="Describe specific resources")
def describe_resources(service_name: str, request: Request, body: ResourceRequest,account_id: str = Query(..., description="AWS account ID"),region: str = Query("us-east-1", description="AWS region")):
    """Describe specific resources under a compute service (EC2, Lambda, ECS)."""
    service_name = service_name.lower()
    
    if service_name not in SUPPORTED_SERVICES:
        raise HTTPException(
            status_code=400,
            detail=f"Service '{service_name}' not supported. Supported services: {SUPPORTED_SERVICES}"
        )
    
    try:
        creds = request.state.session
        details = []

        if service_name == "ec2":
            client = get_aws_client(creds, "ec2", body.region)
            details = describe_ec2_instances(client, body.ids)

        elif service_name == "lambda":
            client = get_aws_client(creds, "lambda", body.region)
            details = describe_lambda_functions(client, body.ids)

        elif service_name == "ecs":
            client = get_aws_client(creds, "ecs", body.region)
            details = describe_ecs_clusters(client, body.ids)

        return {
            "service_name": service_name,
            "region": body.region,
            "count": len(details),
            "details": details
        }

    except ClientError as e:
        handle_aws_error(e, f"describe_resources/{service_name}")
    except AttributeError:
        raise HTTPException(status_code=401, detail="Authentication required")
    except Exception as e:
        logger.error(f"Unexpected error in describe_resources: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))