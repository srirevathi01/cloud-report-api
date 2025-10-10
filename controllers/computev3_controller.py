from fastapi import APIRouter, Request, HTTPException, Query
from pydantic import BaseModel, Field, validator
from typing import List, Dict, Any
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

# --- Request Body Model for POST ---
class ResourceRequest(BaseModel):
    ids:str = Field(..., description="List of resource IDs")

    def get_id_list(self) -> List[str]:
        return [id.strip() for id in self.ids.split(",") if id.strip()]

    @validator('ids')
    def validate_ids(cls, v):
        if not all(isinstance(id, str) and id.strip() for id in v):
            raise ValueError("All IDs must be non-empty strings")
        return v

# --- Helper Functions ---
def get_aws_client(session, service: str, region: str):
    try:
        return session.client(service, region_name=region)
    except Exception as e:
        logger.error(f"Failed to create {service} client: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to create AWS client: {str(e)}")

def handle_aws_error(e: ClientError, context: str = ""):
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
def list_ec2_instances(client) -> List[str]:
    """List only the Instance IDs of EC2 instances"""
    instance_ids = []
    paginator = client.get_paginator('describe_instances')
    for page in paginator.paginate():
        for reservation in page.get("Reservations", []):
            for instance in reservation.get("Instances", []):
                instance_ids.append(instance["InstanceId"])
    return instance_ids

def describe_ec2_instances(client, instance_ids: List[str]) -> List[Dict[str, Any]]:
    """Describe full info of EC2 instances"""
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
                "KeyName": instance.get("KeyName"),
                "Platform": instance.get("Platform", "Linux/UNIX"),
                "IamRole": instance.get("IamInstanceProfile", {}).get("Arn"),
                "Monitoring": instance.get("Monitoring", {}).get("State"),
                "SecurityGroups": [sg["GroupId"] for sg in instance.get("SecurityGroups", [])],
                "Tags": {tag["Key"]: tag["Value"] for tag in instance.get("Tags", [])},
                "BlockDevices": [bd["Ebs"]["VolumeId"] for bd in instance.get("BlockDeviceMappings", [])],
                "StateReason": instance.get("StateReason", {}).get("Message")
            })
    return details

# --- Lambda Functions ---
def list_lambda_functions(client) -> List[str]:
    """List only Lambda function names"""
    names = []
    paginator = client.get_paginator("list_functions")
    for page in paginator.paginate():
        for fn in page.get("Functions", []):
            names.append(fn["FunctionName"])
    return names

def describe_lambda_functions(client, function_names: List[str]) -> List[Dict[str, Any]]:
    """Describe full info of Lambda functions"""
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
                "Layers": [layer["Arn"] for layer in config.get("Layers", [])],
                "Version": config.get("Version"),
                "VpcConfig": config.get("VpcConfig", {}),
                "DeadLetterConfig": config.get("DeadLetterConfig", {}),
                "TracingConfig": config.get("TracingConfig", {}),
                "Tags": client.list_tags(Resource=config.get("FunctionArn")).get("Tags", {}),
                "RevisionId": config.get("RevisionId")
            })
        except ClientError as e:
            if e.response.get('Error', {}).get('Code') == 'ResourceNotFoundException':
                details.append({"FunctionName": fn_name, "Error": "Not found"})
            else:
                raise
    return details

# --- ECS Functions ---
def list_ecs_clusters(client) -> List[str]:
    """List only ECS cluster names"""
    resources = []
    paginator = client.get_paginator('list_clusters')
    for page in paginator.paginate():
        for arn in page.get("clusterArns", []):
            resources.append(arn.split("/")[-1])
    return resources

def describe_ecs_clusters(client, cluster_names: List[str]) -> List[Dict[str, Any]]:
    """Describe full info of ECS clusters, services, and tasks"""
    details = []
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
            # Services and tasks logic (as in previous script)
            try:
                service_arns = []
                paginator_s = client.get_paginator('list_services')
                for page in paginator_s.paginate(cluster=cluster_name):
                    service_arns.extend(page.get("serviceArns", []))
                for j in range(0, len(service_arns), 10):
                    batch_services = service_arns[j:j+10]
                    service_desc = client.describe_services(cluster=cluster_name, services=batch_services)
                    for s in service_desc.get("services", []):
                        service_info = {
                            "ServiceName": s["serviceName"],
                            "ServiceArn": s.get("serviceArn"),
                            "Status": s["status"],
                            "DesiredCount": s["desiredCount"],
                            "RunningCount": s["runningCount"],
                            "PendingCount": s.get("pendingCount", 0),
                            "LaunchType": s.get("launchType", "UNKNOWN"),
                            "TaskDefinition": s.get("taskDefinition"),
                            "Tasks": []
                        }
                        # Tasks (simplified)
                        try:
                            task_arns = []
                            paginator_t = client.get_paginator('list_tasks')
                            for page_task in paginator_t.paginate(cluster=cluster_name, serviceName=s["serviceName"]):
                                task_arns.extend(page_task.get("taskArns", []))
                            for k in range(0, len(task_arns), 100):
                                batch_tasks = task_arns[k:k+100]
                                task_desc = client.describe_tasks(cluster=cluster_name, tasks=batch_tasks)
                                for t in task_desc.get("tasks", []):
                                    service_info["Tasks"].append({
                                        "TaskArn": t["taskArn"],
                                        "TaskDefinitionArn": t.get("taskDefinitionArn"),
                                        "LaunchType": t.get("launchType", "UNKNOWN"),
                                        "LastStatus": t["lastStatus"],
                                        "DesiredStatus": t["desiredStatus"],
                                        "StartedAt": t.get("startedAt").isoformat() if t.get("startedAt") else None,
                                        "StoppedAt": t.get("stoppedAt").isoformat() if t.get("stoppedAt") else None,
                                        "ContainerInstanceArn": t.get("containerInstanceArn"),
                                        "Containers": [
                                            {
                                                "Name": c["name"],
                                                "Image": c["image"],
                                                "Cpu": c.get("cpu"),
                                                "Memory": c.get("memory"),
                                                "ExitCode": c.get("exitCode"),
                                                "LastStatus": c.get("lastStatus"),
                                                "Reason": c.get("reason")
                                            } for c in t.get("containers", [])
                                        ]
                                    })
                        except ClientError as e:
                            logger.warning(f"Error fetching tasks for service {s['ServiceName']}: {str(e)}")
                        cluster_info["Services"].append(service_info)
            except ClientError as e:
                logger.warning(f"Error fetching services for cluster {cluster_name}: {str(e)}")
            details.append(cluster_info)
    return details

# --- API Endpoints ---

# 1. GET /computev3
@router.get("/computev3", summary="List compute services")
def list_compute_services_api(request: Request, account_id: str = Query(...), region: str = Query("us-east-1")):
    return {"compute_services": SUPPORTED_SERVICES}

# 2. GET /computev3/{service_name}/list
@router.get("/computev3/{service_name}/list", summary="List resource names for a service")
def list_service_resources_api(service_name: str, request: Request, account_id: str = Query(...), region: str = Query("us-east-1")):
    service_name = service_name.lower()
    if service_name not in SUPPORTED_SERVICES:
        raise HTTPException(status_code=400, detail=f"Service '{service_name}' not supported")
    session = request.state.session
    resources = []
    try:
        if service_name == "ec2":
            client = get_aws_client(session, "ec2", region)
            resources = list_ec2_instances(client)
        elif service_name == "lambda":
            client = get_aws_client(session, "lambda", region)
            resources = list_lambda_functions(client)
        elif service_name == "ecs":
            client = get_aws_client(session, "ecs", region)
            resources = list_ecs_clusters(client)
        return {"service_name": service_name, "region": region, "resources": resources}
    except ClientError as e:
        handle_aws_error(e, f"list_service_resources/{service_name}")

# 3. POST /computev3/{service_name}
@router.post("/computev3/{service_name}", summary="Describe specific resources")
def describe_resources_api(
    service_name: str,
    request: Request,
    body: ResourceRequest,
    account_id: str = Query(...),
    region: str = Query("us-east-1")
):
    service_name = service_name.lower()
    if service_name not in SUPPORTED_SERVICES:
        raise HTTPException(status_code=400, detail=f"Service '{service_name}' not supported")
    
    session = request.state.session
    details = []
    
    ids_list = body.get_id_list()  # convert string to list

    try:
        if service_name == "ec2":
            client = get_aws_client(session, "ec2", region)
            details = describe_ec2_instances(client, ids_list)
        elif service_name == "lambda":
            client = get_aws_client(session, "lambda", region)
            details = describe_lambda_functions(client, ids_list)
        elif service_name == "ecs":
            client = get_aws_client(session, "ecs", region)
            details = describe_ecs_clusters(client, ids_list)
        
        return {"service_name": service_name, "region": region, "details": details}
    
    except ClientError as e:
        handle_aws_error(e, f"describe_resources/{service_name}")
