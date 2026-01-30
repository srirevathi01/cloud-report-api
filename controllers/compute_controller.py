"""
AWS Compute Services Controller
Handles EC2, Lambda, and ECS resources with comprehensive monitoring and security recommendations
"""

from fastapi import APIRouter, Request, HTTPException, Query, Body
from pydantic import BaseModel, Field, validator
from botocore.exceptions import ClientError, BotoCoreError
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import logging
import time
import boto3

router = APIRouter()
logger = logging.getLogger(__name__)

# ============================================================================
# CONSTANTS
# ============================================================================
COMPUTE_SERVICES = ["ec2", "lambda", "ecs"]
CACHE: Dict[str, Dict[str, Any]] = {}
CACHE_TTL = 300  # 5 minutes

# ============================================================================
# PYDANTIC MODELS
# ============================================================================

class ResourceIdsRequest(BaseModel):
    """Request model for fetching multiple resource details"""
    resource_ids: List[str] = Field(
        ..., 
        min_items=1, 
        max_items=50,
        description="List of resource IDs to fetch details for",
        example=["i-1234567890abcdef0", "i-0987654321fedcba0"]
    )
    
    @validator('resource_ids')
    def validate_resource_ids(cls, v):
        if not all(isinstance(rid, str) and rid.strip() for rid in v):
            raise ValueError("All resource IDs must be non-empty strings")
        return v


class StandardResponse(BaseModel):
    """Standard response format for all APIs"""
    status: str = Field(description="Response status: success or error")
    message: str = Field(description="Human-readable message")
    data: Optional[Any] = Field(default=None, description="Response data")
    errors: Optional[List[str]] = Field(default=None, description="List of errors if any")
    metadata: Optional[Dict[str, Any]] = Field(default=None, description="Additional metadata")


class EC2InstanceBasic(BaseModel):
    """Basic EC2 instance information"""
    InstanceId: str
    Name: Optional[str] = None
    State: str
    InstanceType: str
    LaunchTime: str
    AvailabilityZone: Optional[str] = None
    Tags: List[Dict[str, str]] = []


class EC2InstanceDetail(BaseModel):
    """Detailed EC2 instance information with security analysis"""
    InstanceId: str
    State: str
    InstanceType: str
    LaunchTime: str
    AvailabilityZone: Optional[str] = None
    PublicIpAddress: Optional[str] = None
    PrivateIpAddress: Optional[str] = None
    VpcId: Optional[str] = None
    SubnetId: Optional[str] = None
    SecurityGroups: List[Dict[str, str]] = []
    IamInstanceProfile: Optional[Dict[str, str]] = None
    Tags: List[Dict[str, str]] = []
    Monitoring: Optional[str] = None
    EbsOptimized: bool = False
    RootDeviceType: Optional[str] = None
    BlockDeviceMappings: List[Dict[str, Any]] = []
    recommendations: List[Dict[str, Any]] = []
    security_findings: List[Dict[str, Any]] = []


class LambdaFunctionBasic(BaseModel):
    """Basic Lambda function information"""
    FunctionName: str
    Runtime: str
    LastModified: str
    State: str
    MemorySize: Optional[int] = None


class LambdaFunctionDetail(BaseModel):
    """Detailed Lambda function information with security analysis"""
    FunctionName: str
    FunctionArn: str
    Runtime: str
    Role: str
    Handler: str
    CodeSize: int
    Description: Optional[str] = None
    Timeout: int
    MemorySize: int
    LastModified: str
    State: str
    Version: str
    Environment: Optional[Dict[str, Any]] = None
    VpcConfig: Optional[Dict[str, Any]] = None
    DeadLetterConfig: Optional[Dict[str, Any]] = None
    TracingConfig: Optional[Dict[str, Any]] = None
    Layers: List[str] = []
    Tags: Optional[Dict[str, str]] = None
    recommendations: List[Dict[str, Any]] = []
    security_findings: List[Dict[str, Any]] = []


class ECSClusterBasic(BaseModel):
    """Basic ECS cluster information"""
    ClusterArn: str
    ClusterName: str
    Status: str
    RegisteredContainerInstancesCount: int
    RunningTasksCount: int


class ECSClusterDetail(BaseModel):
    """Detailed ECS cluster information"""
    ClusterArn: str
    ClusterName: str
    Status: str
    RegisteredContainerInstancesCount: int
    RunningTasksCount: int
    PendingTasksCount: int
    ActiveServicesCount: int
    Statistics: List[Dict[str, Any]] = []
    Settings: List[Dict[str, Any]] = []
    Tags: List[Dict[str, str]] = []
    Services: List[str] = []
    recommendations: List[Dict[str, Any]] = []
    security_findings: List[Dict[str, Any]] = []


class ECSServiceDetail(BaseModel):
    """Detailed ECS service information"""
    ServiceArn: str
    ServiceName: str
    ClusterArn: str
    Status: str
    DesiredCount: int
    RunningCount: int
    PendingCount: int
    TaskDefinition: str
    LoadBalancers: List[Dict[str, Any]] = []
    NetworkConfiguration: Optional[Dict[str, Any]] = None
    HealthCheckGracePeriodSeconds: Optional[int] = None
    Tags: List[Dict[str, str]] = []
    recommendations: List[Dict[str, Any]] = []
    security_findings: List[Dict[str, Any]] = []


# ============================================================================
# CACHE HELPERS
# ============================================================================

def get_cache(account_id: str, region: str, service: str, key: str) -> Optional[Any]:
    """Retrieve data from cache if not expired"""
    cache_key = f"{account_id}:{region}:{service}:{key}"
    cached = CACHE.get(cache_key)
    if cached and (time.time() - cached["timestamp"] < CACHE_TTL):
        logger.debug(f"Cache hit for {cache_key}")
        return cached["data"]
    return None


def set_cache(account_id: str, region: str, service: str, key: str, data: Any):
    """Store data in cache with timestamp"""
    cache_key = f"{account_id}:{region}:{service}:{key}"
    CACHE[cache_key] = {"data": data, "timestamp": time.time()}
    logger.debug(f"Cache set for {cache_key}")


# ============================================================================
# ERROR HANDLING
# ============================================================================

def handle_aws_error(e: Exception, context: str) -> HTTPException:
    """Centralized AWS error handling"""
    if isinstance(e, ClientError):
        error_code = e.response.get("Error", {}).get("Code", "Unknown")
        error_msg = e.response.get("Error", {}).get("Message", str(e))
        logger.error(f"AWS Error in {context}: {error_code} - {error_msg}")
        
        status_code = 500
        if error_code in ["AccessDenied", "UnauthorizedOperation", "InvalidClientTokenId"]:
            status_code = 403
        elif error_code in ["InvalidParameterValue", "ValidationError", "InvalidParameterCombination"]:
            status_code = 400
        elif error_code in ["ResourceNotFoundException", "InvalidInstanceID.NotFound"]:
            status_code = 404
        
        return HTTPException(status_code=status_code, detail=f"{error_code}: {error_msg}")
    else:
        logger.error(f"Unexpected error in {context}: {str(e)}")
        return HTTPException(status_code=500, detail=str(e))


# ============================================================================
# EC2 FUNCTIONS
# ============================================================================

def list_ec2_instances(session, account_id: str, region: str) -> List[EC2InstanceBasic]:
    """List all EC2 instances in a region using paginator"""
    cached = get_cache(account_id, region, "ec2", "instances")
    if cached:
        return cached
    
    try:
        ec2_client = session.client("ec2", region_name=region)
        instances = []
        
        paginator = ec2_client.get_paginator("describe_instances")
        for page in paginator.paginate():
            for reservation in page.get("Reservations", []):
                for instance in reservation.get("Instances", []):
                    # Extract tags and find Name tag
                    tags = [{"Key": tag["Key"], "Value": tag["Value"]} for tag in instance.get("Tags", [])]
                    name_tag = next((tag["Value"] for tag in instance.get("Tags", []) if tag["Key"] == "Name"), None)

                    instances.append(EC2InstanceBasic(
                        InstanceId=instance["InstanceId"],
                        Name=name_tag,
                        State=instance["State"]["Name"],
                        InstanceType=instance["InstanceType"],
                        LaunchTime=instance["LaunchTime"].isoformat(),
                        AvailabilityZone=instance.get("Placement", {}).get("AvailabilityZone"),
                        Tags=tags
                    ))
        
        set_cache(account_id, region, "ec2", "instances", instances)
        return instances
    
    except (ClientError, BotoCoreError) as e:
        raise handle_aws_error(e, "list_ec2_instances")


def analyze_ec2_instance(ec2_client, instance_id: str) -> EC2InstanceDetail:
    """Get detailed EC2 instance information with security analysis"""
    try:
        response = ec2_client.describe_instances(InstanceIds=[instance_id])
        
        if not response["Reservations"]:
            raise HTTPException(status_code=404, detail=f"Instance {instance_id} not found")
        
        instance = response["Reservations"][0]["Instances"][0]
        
        # Build detailed instance info
        detail = EC2InstanceDetail(
            InstanceId=instance["InstanceId"],
            State=instance["State"]["Name"],
            InstanceType=instance["InstanceType"],
            LaunchTime=instance["LaunchTime"].isoformat(),
            AvailabilityZone=instance.get("Placement", {}).get("AvailabilityZone"),
            PublicIpAddress=instance.get("PublicIpAddress"),
            PrivateIpAddress=instance.get("PrivateIpAddress"),
            VpcId=instance.get("VpcId"),
            SubnetId=instance.get("SubnetId"),
            SecurityGroups=[
                {"GroupId": sg["GroupId"], "GroupName": sg["GroupName"]}
                for sg in instance.get("SecurityGroups", [])
            ],
            IamInstanceProfile=instance.get("IamInstanceProfile"),
            Tags=[{"Key": tag["Key"], "Value": tag["Value"]} for tag in instance.get("Tags", [])],
            Monitoring=instance.get("Monitoring", {}).get("State"),
            EbsOptimized=instance.get("EbsOptimized", False),
            RootDeviceType=instance.get("RootDeviceType"),
            BlockDeviceMappings=instance.get("BlockDeviceMappings", []),
            recommendations=[],
            security_findings=[]
        )
        
        # Security Analysis
        if detail.PublicIpAddress:
            detail.security_findings.append({
                "type": "security",
                "severity": "high",
                "message": "Instance has a public IP address",
                "recommendation": "Use private subnets and NAT gateway for internet access"
            })
        
        if not detail.IamInstanceProfile:
            detail.security_findings.append({
                "type": "security",
                "severity": "medium",
                "message": "No IAM instance profile attached",
                "recommendation": "Attach IAM role for AWS service access instead of using access keys"
            })
        
        if detail.Monitoring != "enabled":
            detail.recommendations.append({
                "type": "monitoring",
                "severity": "medium",
                "message": "Detailed monitoring not enabled",
                "recommendation": "Enable detailed monitoring for better insights (1-minute metrics)"
            })
        
        if not detail.EbsOptimized:
            detail.recommendations.append({
                "type": "performance",
                "severity": "low",
                "message": "EBS optimization not enabled",
                "recommendation": "Enable EBS optimization for better disk I/O performance"
            })
        
        # Check for unencrypted EBS volumes
        for bdm in detail.BlockDeviceMappings:
            if bdm.get("Ebs"):
                try:
                    volume_id = bdm["Ebs"].get("VolumeId")
                    if volume_id:
                        vol_resp = ec2_client.describe_volumes(VolumeIds=[volume_id])
                        if vol_resp["Volumes"] and not vol_resp["Volumes"][0].get("Encrypted", False):
                            detail.security_findings.append({
                                "type": "security",
                                "severity": "high",
                                "message": f"Unencrypted EBS volume attached: {volume_id}",
                                "recommendation": "Enable EBS encryption for data at rest"
                            })
                except:
                    pass
        
        # Check security groups for open ports
        for sg in detail.SecurityGroups:
            try:
                sg_resp = ec2_client.describe_security_groups(GroupIds=[sg["GroupId"]])
                if sg_resp["SecurityGroups"]:
                    for perm in sg_resp["SecurityGroups"][0].get("IpPermissions", []):
                        for ip_range in perm.get("IpRanges", []):
                            if ip_range.get("CidrIp") == "0.0.0.0/0":
                                from_port = perm.get("FromPort", "All")
                                to_port = perm.get("ToPort", "All")
                                detail.security_findings.append({
                                    "type": "security",
                                    "severity": "critical",
                                    "message": f"Security group {sg['GroupId']} allows unrestricted access from 0.0.0.0/0 on ports {from_port}-{to_port}",
                                    "recommendation": "Restrict security group rules to specific IP ranges"
                                })
            except:
                pass
        
        # Check if instance is stopped (cost optimization)
        if detail.State == "stopped":
            detail.recommendations.append({
                "type": "cost_optimization",
                "severity": "medium",
                "message": "Instance is stopped but still incurring EBS storage costs",
                "recommendation": "Consider terminating if no longer needed or create AMI and terminate"
            })
        
        return detail
        
    except ClientError as e:
        raise handle_aws_error(e, f"analyze_ec2_instance:{instance_id}")


# ============================================================================
# LAMBDA FUNCTIONS
# ============================================================================

def list_lambda_functions(session, account_id: str, region: str) -> List[LambdaFunctionBasic]:
    """List all Lambda functions in a region using paginator"""
    cached = get_cache(account_id, region, "lambda", "functions")
    if cached:
        return cached
    
    try:
        lambda_client = session.client("lambda", region_name=region)
        functions = []
        
        paginator = lambda_client.get_paginator("list_functions")
        for page in paginator.paginate():
            for func in page.get("Functions", []):
                functions.append(LambdaFunctionBasic(
                    FunctionName=func["FunctionName"],
                    Runtime=func["Runtime"],
                    LastModified=func["LastModified"],
                    State=func.get("State", "Active"),
                    MemorySize=func.get("MemorySize")
                ))
        
        set_cache(account_id, region, "lambda", "functions", functions)
        return functions
        
    except (ClientError, BotoCoreError) as e:
        raise handle_aws_error(e, "list_lambda_functions")


def analyze_lambda_function(lambda_client, function_name: str) -> LambdaFunctionDetail:
    """Get detailed Lambda function information with security analysis"""
    try:
        response = lambda_client.get_function(FunctionName=function_name)
        config = response["Configuration"]
        
        # Build detailed function info
        detail = LambdaFunctionDetail(
            FunctionName=config["FunctionName"],
            FunctionArn=config["FunctionArn"],
            Runtime=config["Runtime"],
            Role=config["Role"],
            Handler=config["Handler"],
            CodeSize=config["CodeSize"],
            Description=config.get("Description"),
            Timeout=config["Timeout"],
            MemorySize=config["MemorySize"],
            LastModified=config["LastModified"],
            State=config.get("State", "Active"),
            Version=config["Version"],
            Environment=config.get("Environment"),
            VpcConfig=config.get("VpcConfig"),
            DeadLetterConfig=config.get("DeadLetterConfig"),
            TracingConfig=config.get("TracingConfig"),
            Layers=[layer["Arn"] for layer in config.get("Layers", [])],
            recommendations=[],
            security_findings=[]
        )
        
        # Get tags
        try:
            tags_resp = lambda_client.list_tags(Resource=config["FunctionArn"])
            detail.Tags = tags_resp.get("Tags", {})
        except:
            pass
        
        # Security Analysis
        if detail.Environment and detail.Environment.get("Variables"):
            # Check for potential secrets in environment variables
            sensitive_keys = ["password", "secret", "key", "token", "api_key", "credentials"]
            for key in detail.Environment["Variables"].keys():
                if any(s in key.lower() for s in sensitive_keys):
                    detail.security_findings.append({
                        "type": "security",
                        "severity": "critical",
                        "message": f"Potential secret in environment variable: {key}",
                        "recommendation": "Use AWS Secrets Manager or Parameter Store for sensitive data"
                    })
        
        if not detail.VpcConfig or not detail.VpcConfig.get("VpcId"):
            detail.recommendations.append({
                "type": "security",
                "severity": "medium",
                "message": "Function not running in VPC",
                "recommendation": "Consider running in VPC for accessing private resources securely"
            })
        
        if not detail.DeadLetterConfig:
            detail.recommendations.append({
                "type": "reliability",
                "severity": "medium",
                "message": "Dead letter queue not configured",
                "recommendation": "Configure DLQ (SQS/SNS) to capture failed invocations"
            })
        
        if not detail.TracingConfig or detail.TracingConfig.get("Mode") != "Active":
            detail.recommendations.append({
                "type": "monitoring",
                "severity": "low",
                "message": "X-Ray tracing not enabled",
                "recommendation": "Enable X-Ray for distributed tracing and debugging"
            })
        
        # Check for old runtime
        deprecated_runtimes = ["python3.6", "python3.7", "nodejs10.x", "nodejs12.x", "dotnetcore2.1"]
        if detail.Runtime in deprecated_runtimes:
            detail.security_findings.append({
                "type": "security",
                "severity": "high",
                "message": f"Using deprecated runtime: {detail.Runtime}",
                "recommendation": "Upgrade to a supported runtime version"
            })
        
        # Check timeout
        if detail.Timeout > 300:
            detail.recommendations.append({
                "type": "cost_optimization",
                "severity": "low",
                "message": f"High timeout configured: {detail.Timeout}s",
                "recommendation": "Review if such high timeout is necessary"
            })
        
        # Check memory
        if detail.MemorySize < 512:
            detail.recommendations.append({
                "type": "performance",
                "severity": "low",
                "message": f"Low memory configuration: {detail.MemorySize}MB",
                "recommendation": "Consider increasing memory for better performance (CPU scales with memory)"
            })
        
        return detail
        
    except ClientError as e:
        raise handle_aws_error(e, f"analyze_lambda_function:{function_name}")


# ============================================================================
# ECS FUNCTIONS
# ============================================================================

def list_ecs_clusters(session, account_id: str, region: str) -> List[ECSClusterBasic]:
    """List all ECS clusters in a region using paginator"""
    cached = get_cache(account_id, region, "ecs", "clusters")
    if cached:
        return cached
    
    try:
        ecs_client = session.client("ecs", region_name=region)
        clusters = []
        
        paginator = ecs_client.get_paginator("list_clusters")
        cluster_arns = []
        for page in paginator.paginate():
            cluster_arns.extend(page.get("clusterArns", []))
        
        # Describe clusters in batches of 100
        for i in range(0, len(cluster_arns), 100):
            batch = cluster_arns[i:i+100]
            response = ecs_client.describe_clusters(clusters=batch)
            
            for cluster in response.get("clusters", []):
                clusters.append(ECSClusterBasic(
                    ClusterArn=cluster["clusterArn"],
                    ClusterName=cluster["clusterName"],
                    Status=cluster["status"],
                    RegisteredContainerInstancesCount=cluster.get("registeredContainerInstancesCount", 0),
                    RunningTasksCount=cluster.get("runningTasksCount", 0)
                ))
        
        set_cache(account_id, region, "ecs", "clusters", clusters)
        return clusters
        
    except (ClientError, BotoCoreError) as e:
        raise handle_aws_error(e, "list_ecs_clusters")


def analyze_ecs_cluster(ecs_client, cluster_name: str) -> ECSClusterDetail:
    """Get detailed ECS cluster information with security analysis"""
    try:
        response = ecs_client.describe_clusters(clusters=[cluster_name])
        
        if not response["clusters"]:
            raise HTTPException(status_code=404, detail=f"Cluster {cluster_name} not found")
        
        cluster = response["clusters"][0]
        
        # List services in cluster
        services = []
        try:
            paginator = ecs_client.get_paginator("list_services")
            for page in paginator.paginate(cluster=cluster_name):
                services.extend(page.get("serviceArns", []))
        except:
            pass
        
        # Build detailed cluster info
        detail = ECSClusterDetail(
            ClusterArn=cluster["clusterArn"],
            ClusterName=cluster["clusterName"],
            Status=cluster["status"],
            RegisteredContainerInstancesCount=cluster.get("registeredContainerInstancesCount", 0),
            RunningTasksCount=cluster.get("runningTasksCount", 0),
            PendingTasksCount=cluster.get("pendingTasksCount", 0),
            ActiveServicesCount=cluster.get("activeServicesCount", 0),
            Statistics=cluster.get("statistics", []),
            Settings=cluster.get("settings", []),
            Tags=cluster.get("tags", []),
            Services=[s.split("/")[-1] for s in services],
            recommendations=[],
            security_findings=[]
        )
        
        # Security Analysis
        if detail.RegisteredContainerInstancesCount == 0 and detail.RunningTasksCount == 0:
            detail.recommendations.append({
                "type": "cost_optimization",
                "severity": "high",
                "message": "Cluster has no running tasks or instances",
                "recommendation": "Consider deleting unused cluster to avoid confusion"
            })
        
        # Check for container insights
        insights_enabled = any(
            s.get("name") == "containerInsights" and s.get("value") == "enabled"
            for s in detail.Settings
        )
        if not insights_enabled:
            detail.recommendations.append({
                "type": "monitoring",
                "severity": "medium",
                "message": "Container Insights not enabled",
                "recommendation": "Enable Container Insights for enhanced monitoring and observability"
            })
        
        return detail
        
    except ClientError as e:
        raise handle_aws_error(e, f"analyze_ecs_cluster:{cluster_name}")


def list_ecs_services(ecs_client, cluster_name: str) -> List[str]:
    """List all services in an ECS cluster"""
    try:
        services = []
        paginator = ecs_client.get_paginator("list_services")
        for page in paginator.paginate(cluster=cluster_name):
            services.extend([s.split("/")[-1] for s in page.get("serviceArns", [])])
        return services
    except (ClientError, BotoCoreError) as e:
        raise handle_aws_error(e, f"list_ecs_services:{cluster_name}")


def analyze_ecs_service(ecs_client, cluster_name: str, service_name: str) -> ECSServiceDetail:
    """Get detailed ECS service information with security analysis"""
    try:
        response = ecs_client.describe_services(cluster=cluster_name, services=[service_name])
        
        if not response["services"]:
            raise HTTPException(status_code=404, detail=f"Service {service_name} not found in cluster {cluster_name}")
        
        service = response["services"][0]
        
        # Build detailed service info
        detail = ECSServiceDetail(
            ServiceArn=service["serviceArn"],
            ServiceName=service["serviceName"],
            ClusterArn=service["clusterArn"],
            Status=service["status"],
            DesiredCount=service["desiredCount"],
            RunningCount=service["runningCount"],
            PendingCount=service["pendingCount"],
            TaskDefinition=service["taskDefinition"],
            LoadBalancers=service.get("loadBalancers", []),
            NetworkConfiguration=service.get("networkConfiguration"),
            HealthCheckGracePeriodSeconds=service.get("healthCheckGracePeriodSeconds"),
            Tags=service.get("tags", []),
            recommendations=[],
            security_findings=[]
        )
        
        # Security Analysis
        if detail.DesiredCount != detail.RunningCount:
            detail.recommendations.append({
                "type": "availability",
                "severity": "high",
                "message": f"Desired count ({detail.DesiredCount}) doesn't match running count ({detail.RunningCount})",
                "recommendation": "Investigate why tasks are not running as expected"
            })
        
        if detail.DesiredCount < 2:
            detail.recommendations.append({
                "type": "availability",
                "severity": "medium",
                "message": "Service has less than 2 tasks",
                "recommendation": "Run at least 2 tasks across multiple AZs for high availability"
            })
        
        if not detail.LoadBalancers:
            detail.recommendations.append({
                "type": "architecture",
                "severity": "low",
                "message": "No load balancer attached to service",
                "recommendation": "Consider using ALB/NLB for better traffic distribution and health checks"
            })
        
        # Check network mode
        if detail.NetworkConfiguration:
            subnets = detail.NetworkConfiguration.get("awsvpcConfiguration", {}).get("subnets", [])
            if len(subnets) < 2:
                detail.recommendations.append({
                    "type": "availability",
                    "severity": "medium",
                    "message": "Service running in single subnet",
                    "recommendation": "Deploy across multiple subnets in different AZs for high availability"
                })
            
            assign_public_ip = detail.NetworkConfiguration.get("awsvpcConfiguration", {}).get("assignPublicIp")
            if assign_public_ip == "ENABLED":
                detail.security_findings.append({
                    "type": "security",
                    "severity": "medium",
                    "message": "Tasks are assigned public IP addresses",
                    "recommendation": "Use private subnets with NAT gateway for outbound internet access"
                })
        
        return detail
        
    except ClientError as e:
        raise handle_aws_error(e, f"analyze_ecs_service:{cluster_name}/{service_name}")


# ============================================================================
# API ROUTES
# ============================================================================

@router.get(
    "/compute/{service}",
    response_model=StandardResponse,
    summary="List all resources for a compute service",
    description="Returns a list of all resources (EC2 instances, Lambda functions, or ECS clusters) in the specified region",
    responses={
        200: {
            "description": "Successful response",
            "content": {
                "application/json": {
                    "examples": {
                        "ec2": {
                            "summary": "EC2 Instances Example",
                            "value": {
                                "status": "success",
                                "message": "Retrieved 5 EC2 instances",
                                "data": [
                                    {
                                        "InstanceId": "i-1234567890abcdef0",
                                        "State": "running",
                                        "InstanceType": "t3.medium",
                                        "LaunchTime": "2024-01-15T10:30:00Z",
                                        "AvailabilityZone": "us-east-1a"
                                    }
                                ],
                                "metadata": {
                                    "total_count": 5,
                                    "service": "ec2",
                                    "account_id": "123456789012",
                                    "region": "us-east-1"
                                }
                            }
                        },
                        "lambda": {
                            "summary": "Lambda Functions Example",
                            "value": {
                                "status": "success",
                                "message": "Retrieved 10 Lambda functions",
                                "data": [
                                    {
                                        "FunctionName": "my-api-function",
                                        "Runtime": "python3.11",
                                        "LastModified": "2024-01-15T10:30:00Z",
                                        "State": "Active",
                                        "MemorySize": 512
                                    }
                                ],
                                "metadata": {
                                    "total_count": 10,
                                    "service": "lambda",
                                    "account_id": "123456789012",
                                    "region": "us-east-1"
                                }
                            }
                        },
                        "ecs": {
                            "summary": "ECS Clusters Example",
                            "value": {
                                "status": "success",
                                "message": "Retrieved 3 ECS clusters",
                                "data": [
                                    {
                                        "ClusterArn": "arn:aws:ecs:us-east-1:123456789012:cluster/production",
                                        "ClusterName": "production",
                                        "Status": "ACTIVE",
                                        "RegisteredContainerInstancesCount": 5,
                                        "RunningTasksCount": 20
                                    }
                                ],
                                "metadata": {
                                    "total_count": 3,
                                    "service": "ecs",
                                    "account_id": "123456789012",
                                    "region": "us-east-1"
                                }
                            }
                        }
                    }
                }
            }
        }
    }
)
async def list_compute_resources(
    request: Request,
    service: str,
    account_id: str = Query(..., description="AWS Account ID", example="123456789012"),
    region: str = Query("us-east-1", description="AWS Region", example="us-east-1")
):
    """List all resources for a specific compute service (ec2, lambda, or ecs)"""
    
    if service not in COMPUTE_SERVICES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid service '{service}'. Supported services: {', '.join(COMPUTE_SERVICES)}"
        )
    print (request)
    session = getattr(request.state, "session", None)
    if not session:
        raise HTTPException(status_code=401, detail="AWS session not found")
    
    try:
        if service == "ec2":
            resources = list_ec2_instances(session, account_id, region)
            data = [inst.dict() for inst in resources]
        elif service == "lambda":
            resources = list_lambda_functions(session, account_id, region)
            data = [func.dict() for func in resources]
        elif service == "ecs":
            resources = list_ecs_clusters(session, account_id, region)
            data = [cluster.dict() for cluster in resources]
        
        return StandardResponse(
            status="success",
            message=f"Retrieved {len(resources)} {service} resources",
            data=data,
            metadata={
                "total_count": len(resources),
                "service": service,
                "account_id": account_id,
                "region": region
            }
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Unexpected error in list_compute_resources for {service}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post(
    "/compute/{service}",
    response_model=StandardResponse,
    summary="Get detailed resource information for a compute service",
    description="Returns detailed information and security analysis for specified resources (EC2 instances, Lambda functions, or ECS clusters)",
    responses={
        200: {
            "description": "Successful response",
            "content": {
                "application/json": {
                    "examples": {
                        "ec2": {
                            "summary": "EC2 Details Example",
                            "value": {
                                "status": "success",
                                "message": "Retrieved details for 1 instances",
                                "data": [
                                    {
                                        "InstanceId": "i-1234567890abcdef0",
                                        "State": "running",
                                        "InstanceType": "t3.medium",
                                        "PublicIpAddress": "54.123.45.67",
                                        "VpcId": "vpc-12345678",
                                        "SecurityGroups": [{"GroupId": "sg-12345678", "GroupName": "web-sg"}],
                                        "security_findings": [
                                            {
                                                "type": "security",
                                                "severity": "high",
                                                "message": "Instance has a public IP address",
                                                "recommendation": "Use private subnets and NAT gateway"
                                            }
                                        ],
                                        "recommendations": [
                                            {
                                                "type": "monitoring",
                                                "severity": "medium",
                                                "message": "Detailed monitoring not enabled"
                                            }
                                        ]
                                    }
                                ],
                                "metadata": {
                                    "requested_count": 1,
                                    "successful_count": 1,
                                    "failed_count": 0,
                                    "service": "ec2",
                                    "account_id": "123456789012",
                                    "region": "us-east-1"
                                }
                            }
                        },
                        "lambda": {
                            "summary": "Lambda Details Example",
                            "value": {
                                "status": "success",
                                "message": "Retrieved details for 1 functions",
                                "data": [
                                    {
                                        "FunctionName": "my-api-function",
                                        "Runtime": "python3.11",
                                        "MemorySize": 512,
                                        "Timeout": 30,
                                        "Environment": {"Variables": {"API_KEY": "****"}},
                                        "security_findings": [
                                            {
                                                "type": "security",
                                                "severity": "critical",
                                                "message": "Potential secret in environment variable: API_KEY",
                                                "recommendation": "Use AWS Secrets Manager or Parameter Store"
                                            }
                                        ],
                                        "recommendations": [
                                            {
                                                "type": "reliability",
                                                "severity": "medium",
                                                "message": "Dead letter queue not configured"
                                            }
                                        ]
                                    }
                                ],
                                "metadata": {
                                    "requested_count": 1,
                                    "successful_count": 1,
                                    "failed_count": 0,
                                    "service": "lambda",
                                    "account_id": "123456789012",
                                    "region": "us-east-1"
                                }
                            }
                        },
                        "ecs": {
                            "summary": "ECS Cluster Details Example",
                            "value": {
                                "status": "success",
                                "message": "Retrieved details for 1 clusters",
                                "data": [
                                    {
                                        "ClusterName": "production",
                                        "Status": "ACTIVE",
                                        "RunningTasksCount": 20,
                                        "Services": ["api-service", "worker-service"],
                                        "recommendations": [
                                            {
                                                "type": "monitoring",
                                                "severity": "medium",
                                                "message": "Container Insights not enabled",
                                                "recommendation": "Enable Container Insights for enhanced monitoring"
                                            }
                                        ]
                                    }
                                ],
                                "metadata": {
                                    "requested_count": 1,
                                    "successful_count": 1,
                                    "failed_count": 0,
                                    "service": "ecs",
                                    "account_id": "123456789012",
                                    "region": "us-east-1"
                                }
                            }
                        }
                    }
                }
            }
        }
    }
)
async def get_compute_details(
    request: Request,
    service: str,
    payload: ResourceIdsRequest = Body(...),
    account_id: str = Query(..., description="AWS Account ID"),
    region: str = Query("us-east-1", description="AWS Region")
):
    """Get detailed information for multiple resources of a specific compute service"""
    
    if service not in COMPUTE_SERVICES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid service '{service}'. Supported services: {', '.join(COMPUTE_SERVICES)}"
        )
    
    session = getattr(request.state, "session", None)
    if not session:
        raise HTTPException(status_code=401, detail="AWS session not found")
    
    try:
        details = []
        errors = []
        
        if service == "ec2":
            ec2_client = session.client("ec2", region_name=region)
            for instance_id in payload.resource_ids:
                try:
                    detail = analyze_ec2_instance(ec2_client, instance_id)
                    details.append(detail.dict())
                except HTTPException as he:
                    errors.append(f"{instance_id}: {he.detail}")
                except Exception as e:
                    errors.append(f"{instance_id}: {str(e)}")
        
        elif service == "lambda":
            lambda_client = session.client("lambda", region_name=region)
            for function_name in payload.resource_ids:
                try:
                    detail = analyze_lambda_function(lambda_client, function_name)
                    details.append(detail.dict())
                except HTTPException as he:
                    errors.append(f"{function_name}: {he.detail}")
                except Exception as e:
                    errors.append(f"{function_name}: {str(e)}")
        
        elif service == "ecs":
            ecs_client = session.client("ecs", region_name=region)
            for cluster_name in payload.resource_ids:
                try:
                    detail = analyze_ecs_cluster(ecs_client, cluster_name)
                    details.append(detail.dict())
                except HTTPException as he:
                    errors.append(f"{cluster_name}: {he.detail}")
                except Exception as e:
                    errors.append(f"{cluster_name}: {str(e)}")
        
        return StandardResponse(
            status="success" if details else "error",
            message=f"Retrieved details for {len(details)} {service} resources",
            data=details,
            errors=errors if errors else None,
            metadata={
                "requested_count": len(payload.resource_ids),
                "successful_count": len(details),
                "failed_count": len(errors),
                "service": service,
                "account_id": account_id,
                "region": region
            }
        )
    except Exception as e:
        logger.exception(f"Unexpected error in get_compute_details for {service}")
        raise HTTPException(status_code=500, detail=str(e))