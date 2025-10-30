"""
AWS Storage Services Controller
Handles S3, EBS, and EFS resources with comprehensive security and cost optimization recommendations
"""

from fastapi import APIRouter, Request, HTTPException, Query, Body
from pydantic import BaseModel, Field, validator
from botocore.exceptions import ClientError, BotoCoreError
from typing import Dict, Any, List, Optional
from datetime import datetime
import logging
import time

router = APIRouter()
logger = logging.getLogger(__name__)

# ============================================================================
# CONSTANTS
# ============================================================================
STORAGE_SERVICES = ["s3", "ebs", "efs"]
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
        example=["my-bucket-name", "vol-1234567890abcdef0"]
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


class S3BucketBasic(BaseModel):
    """Basic S3 bucket information"""
    Name: str
    CreationDate: str
    Region: Optional[str] = None


class S3BucketDetail(BaseModel):
    """Detailed S3 bucket information with security analysis"""
    Name: str
    CreationDate: str
    Region: str
    Versioning: str
    Encryption: Optional[Dict[str, Any]] = None
    PublicAccessBlock: Optional[Dict[str, Any]] = None
    Logging: bool
    LifecyclePolicies: List[Dict[str, Any]] = []
    Tags: List[Dict[str, str]] = []
    MFADelete: str
    ObjectOwnership: Optional[str] = None
    ReplicationConfiguration: Optional[Dict[str, Any]] = None
    recommendations: List[Dict[str, Any]] = []
    security_findings: List[Dict[str, Any]] = []


class EBSVolumeBasic(BaseModel):
    """Basic EBS volume information"""
    VolumeId: str
    Size: int
    VolumeType: str
    State: str
    Encrypted: bool
    AvailabilityZone: Optional[str] = None


class EBSVolumeDetail(BaseModel):
    """Detailed EBS volume information with security analysis"""
    VolumeId: str
    Size: int
    VolumeType: str
    State: str
    Encrypted: bool
    KmsKeyId: Optional[str] = None
    Iops: Optional[int] = None
    Throughput: Optional[int] = None
    SnapshotId: Optional[str] = None
    AvailabilityZone: str
    CreateTime: str
    Attachments: List[Dict[str, Any]] = []
    Tags: List[Dict[str, str]] = []
    MultiAttachEnabled: bool = False
    recommendations: List[Dict[str, Any]] = []
    security_findings: List[Dict[str, Any]] = []


class EFSFileSystemBasic(BaseModel):
    """Basic EFS filesystem information"""
    FileSystemId: str
    Name: Optional[str] = None
    PerformanceMode: str
    ThroughputMode: str
    Encrypted: bool
    LifeCycleState: str


class EFSFileSystemDetail(BaseModel):
    """Detailed EFS filesystem information with security analysis"""
    FileSystemId: str
    FileSystemArn: str
    Name: Optional[str] = None
    CreationTime: str
    LifeCycleState: str
    NumberOfMountTargets: int
    SizeInBytes: Dict[str, Any]
    PerformanceMode: str
    Encrypted: bool
    KmsKeyId: Optional[str] = None
    ThroughputMode: str
    ProvisionedThroughputInMibps: Optional[float] = None
    LifecyclePolicies: List[Dict[str, Any]] = []
    FileSystemPolicy: Optional[Dict[str, Any]] = None
    BackupPolicy: Optional[Dict[str, Any]] = None
    Tags: List[Dict[str, str]] = []
    MountTargets: List[Dict[str, Any]] = []
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
        elif error_code in ["NoSuchBucket", "NoSuchVolume", "FileSystemNotFound"]:
            status_code = 404
        
        return HTTPException(status_code=status_code, detail=f"{error_code}: {error_msg}")
    else:
        logger.error(f"Unexpected error in {context}: {str(e)}")
        return HTTPException(status_code=500, detail=str(e))


# ============================================================================
# S3 FUNCTIONS
# ============================================================================

def list_s3_buckets(session, account_id: str, region: str) -> List[S3BucketBasic]:
    """List all S3 buckets in the specified region"""
    cached = get_cache(account_id, region, "s3", "buckets")
    if cached:
        return cached
    
    try:
        s3_client = session.client("s3")
        buckets = []
        
        response = s3_client.list_buckets()
        for bucket in response.get("Buckets", []):
            try:
                # Get bucket region
                location = s3_client.get_bucket_location(Bucket=bucket["Name"])
                bucket_region = location.get("LocationConstraint") or "us-east-1"
                
                # Filter by region
                if bucket_region == region:
                    buckets.append(S3BucketBasic(
                        Name=bucket["Name"],
                        CreationDate=bucket["CreationDate"].isoformat(),
                        Region=bucket_region
                    ))
            except ClientError as e:
                # Skip buckets we can't access
                logger.warning(f"Cannot access bucket {bucket['Name']}: {e}")
                continue
        
        set_cache(account_id, region, "s3", "buckets", buckets)
        return buckets
        
    except (ClientError, BotoCoreError) as e:
        raise handle_aws_error(e, "list_s3_buckets")


def analyze_s3_bucket(s3_client, bucket_name: str) -> S3BucketDetail:
    """Get detailed S3 bucket information with security analysis"""
    try:
        # Get bucket creation date and region
        buckets_response = s3_client.list_buckets()
        bucket_info = next((b for b in buckets_response["Buckets"] if b["Name"] == bucket_name), None)
        
        if not bucket_info:
            raise HTTPException(status_code=404, detail=f"Bucket {bucket_name} not found")
        
        location = s3_client.get_bucket_location(Bucket=bucket_name)
        bucket_region = location.get("LocationConstraint") or "us-east-1"
        
        # Initialize detail object
        detail = S3BucketDetail(
            Name=bucket_name,
            CreationDate=bucket_info["CreationDate"].isoformat(),
            Region=bucket_region,
            Versioning="Disabled",
            Logging=False,
            MFADelete="Disabled",
            LifecyclePolicies=[],
            Tags=[],
            recommendations=[],
            security_findings=[]
        )
        
        # Versioning
        try:
            versioning = s3_client.get_bucket_versioning(Bucket=bucket_name)
            detail.Versioning = versioning.get("Status", "Disabled")
            detail.MFADelete = versioning.get("MFADelete", "Disabled")
            
            if detail.Versioning != "Enabled":
                detail.recommendations.append({
                    "type": "data_protection",
                    "severity": "medium",
                    "message": "Bucket versioning not enabled",
                    "recommendation": "Enable versioning to protect against accidental deletions and overwrites"
                })
            
            if detail.MFADelete != "Enabled":
                detail.security_findings.append({
                    "type": "security",
                    "severity": "high",
                    "message": "MFA Delete not enabled",
                    "recommendation": "Enable MFA Delete for additional protection against accidental deletions"
                })
        except ClientError:
            pass
        
        # Encryption
        try:
            encryption = s3_client.get_bucket_encryption(Bucket=bucket_name)
            detail.Encryption = encryption.get("ServerSideEncryptionConfiguration", {})
        except ClientError:
            detail.security_findings.append({
                "type": "security",
                "severity": "high",
                "message": "Bucket encryption not enabled",
                "recommendation": "Enable default encryption (AES-256 or KMS) for data at rest"
            })
        
        # Public Access Block
        try:
            pab = s3_client.get_public_access_block(Bucket=bucket_name)
            detail.PublicAccessBlock = pab["PublicAccessBlockConfiguration"]
            
            if not all([
                detail.PublicAccessBlock.get("BlockPublicAcls"),
                detail.PublicAccessBlock.get("IgnorePublicAcls"),
                detail.PublicAccessBlock.get("BlockPublicPolicy"),
                detail.PublicAccessBlock.get("RestrictPublicBuckets")
            ]):
                detail.security_findings.append({
                    "type": "security",
                    "severity": "critical",
                    "message": "Public access block not fully configured",
                    "recommendation": "Block all public access unless specifically required"
                })
        except ClientError:
            detail.security_findings.append({
                "type": "security",
                "severity": "critical",
                "message": "Public access block not configured",
                "recommendation": "Configure public access block settings to prevent accidental public exposure"
            })
        
        # Logging
        try:
            logging_config = s3_client.get_bucket_logging(Bucket=bucket_name)
            detail.Logging = "LoggingEnabled" in logging_config
            
            if not detail.Logging:
                detail.recommendations.append({
                    "type": "monitoring",
                    "severity": "medium",
                    "message": "Server access logging not enabled",
                    "recommendation": "Enable access logging for audit and compliance requirements"
                })
        except ClientError:
            pass
        
        # Lifecycle Policies
        try:
            lifecycle = s3_client.get_bucket_lifecycle_configuration(Bucket=bucket_name)
            detail.LifecyclePolicies = lifecycle.get("Rules", [])
        except ClientError:
            detail.recommendations.append({
                "type": "cost_optimization",
                "severity": "medium",
                "message": "No lifecycle policy configured",
                "recommendation": "Configure lifecycle policies to automatically transition objects to cheaper storage classes"
            })
        
        # Tags
        try:
            tags = s3_client.get_bucket_tagging(Bucket=bucket_name)
            detail.Tags = tags.get("TagSet", [])
        except ClientError:
            pass
        
        # Object Ownership
        try:
            ownership = s3_client.get_bucket_ownership_controls(Bucket=bucket_name)
            rules = ownership.get("OwnershipControls", {}).get("Rules", [])
            if rules:
                detail.ObjectOwnership = rules[0].get("ObjectOwnership")
                
            if detail.ObjectOwnership != "BucketOwnerEnforced":
                detail.security_findings.append({
                    "type": "security",
                    "severity": "high",
                    "message": "Object ownership not enforced",
                    "recommendation": "Set object ownership to BucketOwnerEnforced to disable ACLs"
                })
        except ClientError:
            pass
        
        # Replication Configuration
        try:
            replication = s3_client.get_bucket_replication(Bucket=bucket_name)
            detail.ReplicationConfiguration = replication.get("ReplicationConfiguration")
        except ClientError:
            # Replication is optional, not a finding
            pass
        
        # Check for public buckets
        try:
            acl = s3_client.get_bucket_acl(Bucket=bucket_name)
            for grant in acl.get("Grants", []):
                grantee = grant.get("Grantee", {})
                if grantee.get("Type") == "Group" and "AllUsers" in grantee.get("URI", ""):
                    detail.security_findings.append({
                        "type": "security",
                        "severity": "critical",
                        "message": "Bucket has public ACL permissions",
                        "recommendation": "Remove public ACL grants immediately"
                    })
        except ClientError:
            pass
        
        return detail
        
    except ClientError as e:
        raise handle_aws_error(e, f"analyze_s3_bucket:{bucket_name}")


# ============================================================================
# EBS FUNCTIONS
# ============================================================================

def list_ebs_volumes(session, account_id: str, region: str) -> List[EBSVolumeBasic]:
    """List all EBS volumes in a region using paginator"""
    cached = get_cache(account_id, region, "ebs", "volumes")
    if cached:
        return cached
    
    try:
        ec2_client = session.client("ec2", region_name=region)
        volumes = []
        
        paginator = ec2_client.get_paginator("describe_volumes")
        for page in paginator.paginate():
            for volume in page.get("Volumes", []):
                volumes.append(EBSVolumeBasic(
                    VolumeId=volume["VolumeId"],
                    Size=volume["Size"],
                    VolumeType=volume["VolumeType"],
                    State=volume["State"],
                    Encrypted=volume["Encrypted"],
                    AvailabilityZone=volume.get("AvailabilityZone")
                ))
        
        set_cache(account_id, region, "ebs", "volumes", volumes)
        return volumes
        
    except (ClientError, BotoCoreError) as e:
        raise handle_aws_error(e, "list_ebs_volumes")


def analyze_ebs_volume(ec2_client, volume_id: str) -> EBSVolumeDetail:
    """Get detailed EBS volume information with security analysis"""
    try:
        response = ec2_client.describe_volumes(VolumeIds=[volume_id])
        
        if not response["Volumes"]:
            raise HTTPException(status_code=404, detail=f"Volume {volume_id} not found")
        
        volume = response["Volumes"][0]
        
        # Get tags
        tags = [{"Key": tag["Key"], "Value": tag["Value"]} for tag in volume.get("Tags", [])]
        
        # Build detailed volume info
        detail = EBSVolumeDetail(
            VolumeId=volume["VolumeId"],
            Size=volume["Size"],
            VolumeType=volume["VolumeType"],
            State=volume["State"],
            Encrypted=volume["Encrypted"],
            KmsKeyId=volume.get("KmsKeyId"),
            Iops=volume.get("Iops"),
            Throughput=volume.get("Throughput"),
            SnapshotId=volume.get("SnapshotId"),
            AvailabilityZone=volume["AvailabilityZone"],
            CreateTime=volume["CreateTime"].isoformat(),
            Attachments=volume.get("Attachments", []),
            Tags=tags,
            MultiAttachEnabled=volume.get("MultiAttachEnabled", False),
            recommendations=[],
            security_findings=[]
        )
        
        # Security Analysis
        if not detail.Encrypted:
            detail.security_findings.append({
                "type": "security",
                "severity": "high",
                "message": "Volume is not encrypted",
                "recommendation": "Enable encryption for data at rest protection"
            })
        
        # Check if volume is unattached
        if not detail.Attachments:
            detail.recommendations.append({
                "type": "cost_optimization",
                "severity": "high",
                "message": "Volume is not attached to any instance",
                "recommendation": "Delete unused volumes or create snapshot and delete to save costs"
            })
        
        # Check for old volume types
        if detail.VolumeType == "gp2":
            detail.recommendations.append({
                "type": "performance",
                "severity": "low",
                "message": "Using older gp2 volume type",
                "recommendation": "Consider migrating to gp3 for better performance and lower cost"
            })
        
        if detail.VolumeType == "standard":
            detail.recommendations.append({
                "type": "performance",
                "severity": "medium",
                "message": "Using magnetic (standard) volume type",
                "recommendation": "Migrate to SSD-based volumes (gp3, gp2, io1, io2) for better performance"
            })
        
        # Check for oversized volumes
        if detail.State == "available" and detail.Size > 100:
            detail.recommendations.append({
                "type": "cost_optimization",
                "severity": "medium",
                "message": f"Large unattached volume ({detail.Size} GB)",
                "recommendation": "Review if this volume is still needed"
            })
        
        # Check snapshot backup
        try:
            snapshots = ec2_client.describe_snapshots(
                Filters=[{"Name": "volume-id", "Values": [volume_id]}],
                OwnerIds=["self"]
            )
            if not snapshots["Snapshots"]:
                detail.recommendations.append({
                    "type": "backup",
                    "severity": "medium",
                    "message": "No snapshots found for this volume",
                    "recommendation": "Create regular snapshots for disaster recovery"
                })
        except ClientError:
            pass
        
        return detail
        
    except ClientError as e:
        raise handle_aws_error(e, f"analyze_ebs_volume:{volume_id}")


# ============================================================================
# EFS FUNCTIONS
# ============================================================================

def list_efs_filesystems(session, account_id: str, region: str) -> List[EFSFileSystemBasic]:
    """List all EFS filesystems in a region using paginator"""
    cached = get_cache(account_id, region, "efs", "filesystems")
    if cached:
        return cached
    
    try:
        efs_client = session.client("efs", region_name=region)
        filesystems = []
        
        paginator = efs_client.get_paginator("describe_file_systems")
        for page in paginator.paginate():
            for fs in page.get("FileSystems", []):
                name = None
                for tag in fs.get("Tags", []):
                    if tag.get("Key") == "Name":
                        name = tag.get("Value")
                        break
                
                filesystems.append(EFSFileSystemBasic(
                    FileSystemId=fs["FileSystemId"],
                    Name=name,
                    PerformanceMode=fs["PerformanceMode"],
                    ThroughputMode=fs.get("ThroughputMode", "bursting"),
                    Encrypted=fs["Encrypted"],
                    LifeCycleState=fs["LifeCycleState"]
                ))
        
        set_cache(account_id, region, "efs", "filesystems", filesystems)
        return filesystems
        
    except (ClientError, BotoCoreError) as e:
        raise handle_aws_error(e, "list_efs_filesystems")


def analyze_efs_filesystem(efs_client, filesystem_id: str) -> EFSFileSystemDetail:
    """Get detailed EFS filesystem information with security analysis"""
    try:
        response = efs_client.describe_file_systems(FileSystemId=filesystem_id)
        
        if not response["FileSystems"]:
            raise HTTPException(status_code=404, detail=f"Filesystem {filesystem_id} not found")
        
        fs = response["FileSystems"][0]
        
        # Get name from tags
        name = None
        tags = [{"Key": tag["Key"], "Value": tag["Value"]} for tag in fs.get("Tags", [])]
        for tag in tags:
            if tag["Key"] == "Name":
                name = tag["Value"]
                break
        
        # Build detailed filesystem info
        detail = EFSFileSystemDetail(
            FileSystemId=fs["FileSystemId"],
            FileSystemArn=fs["FileSystemArn"],
            Name=name,
            CreationTime=fs["CreationTime"].isoformat(),
            LifeCycleState=fs["LifeCycleState"],
            NumberOfMountTargets=fs["NumberOfMountTargets"],
            SizeInBytes=fs["SizeInBytes"],
            PerformanceMode=fs["PerformanceMode"],
            Encrypted=fs["Encrypted"],
            KmsKeyId=fs.get("KmsKeyId"),
            ThroughputMode=fs.get("ThroughputMode", "bursting"),
            ProvisionedThroughputInMibps=fs.get("ProvisionedThroughputInMibps"),
            Tags=tags,
            MountTargets=[],
            recommendations=[],
            security_findings=[]
        )
        
        # Security Analysis
        if not detail.Encrypted:
            detail.security_findings.append({
                "type": "security",
                "severity": "high",
                "message": "Filesystem is not encrypted",
                "recommendation": "Enable encryption at rest for data protection"
            })
        
        # Get lifecycle policies
        try:
            lifecycle = efs_client.describe_lifecycle_configuration(FileSystemId=filesystem_id)
            detail.LifecyclePolicies = lifecycle.get("LifecyclePolicies", [])
            
            if not detail.LifecyclePolicies:
                detail.recommendations.append({
                    "type": "cost_optimization",
                    "severity": "medium",
                    "message": "No lifecycle policies configured",
                    "recommendation": "Configure lifecycle management to automatically move infrequently accessed files to IA storage class"
                })
        except ClientError:
            pass
        
        # Get filesystem policy
        try:
            policy_resp = efs_client.describe_file_system_policy(FileSystemId=filesystem_id)
            detail.FileSystemPolicy = policy_resp.get("Policy")
        except ClientError:
            detail.recommendations.append({
                "type": "security",
                "severity": "low",
                "message": "No filesystem policy configured",
                "recommendation": "Consider using filesystem policies for fine-grained access control"
            })
        
        # Get backup policy
        try:
            backup_resp = efs_client.describe_backup_policy(FileSystemId=filesystem_id)
            detail.BackupPolicy = backup_resp.get("BackupPolicy")
            
            if not detail.BackupPolicy or detail.BackupPolicy.get("Status") != "ENABLED":
                detail.recommendations.append({
                    "type": "backup",
                    "severity": "high",
                    "message": "Automatic backups not enabled",
                    "recommendation": "Enable AWS Backup for automatic filesystem backups"
                })
        except ClientError:
            pass
        
        # Get mount targets
        try:
            mount_targets = efs_client.describe_mount_targets(FileSystemId=filesystem_id)
            detail.MountTargets = mount_targets.get("MountTargets", [])
            
            if len(detail.MountTargets) < 2:
                detail.recommendations.append({
                    "type": "availability",
                    "severity": "medium",
                    "message": "Filesystem has mount targets in less than 2 availability zones",
                    "recommendation": "Create mount targets in multiple AZs for high availability"
                })
        except ClientError:
            pass
        
        # Performance mode recommendations
        if detail.PerformanceMode == "generalPurpose":
            detail.recommendations.append({
                "type": "performance",
                "severity": "low",
                "message": "Using generalPurpose performance mode",
                "recommendation": "Consider maxIO mode for workloads requiring higher throughput and IOPS"
            })
        
        # Throughput mode recommendations
        if detail.ThroughputMode == "bursting":
            size_gb = detail.SizeInBytes.get("Value", 0) / (1024**3)
            if size_gb < 100:
                detail.recommendations.append({
                    "type": "performance",
                    "severity": "low",
                    "message": "Small filesystem with bursting throughput mode",
                    "recommendation": "Consider provisioned throughput for consistent performance"
                })
        
        return detail
        
    except ClientError as e:
        raise handle_aws_error(e, f"analyze_efs_filesystem:{filesystem_id}")


# ============================================================================
# API ROUTES
# ============================================================================

@router.get(
    "/storage/{service}",
    response_model=StandardResponse,
    summary="List all resources for a storage service",
    description="Returns a list of all resources (S3 buckets, EBS volumes, or EFS filesystems) in the specified region",
    responses={
        200: {
            "description": "Successful response",
            "content": {
                "application/json": {
                    "examples": {
                        "s3": {
                            "summary": "S3 Buckets Example",
                            "value": {
                                "status": "success",
                                "message": "Retrieved 15 S3 buckets",
                                "data": [
                                    {
                                        "Name": "my-application-logs",
                                        "CreationDate": "2024-01-15T10:30:00Z",
                                        "Region": "us-east-1"
                                    }
                                ],
                                "metadata": {
                                    "total_count": 15,
                                    "service": "s3",
                                    "account_id": "123456789012",
                                    "region": "us-east-1"
                                }
                            }
                        },
                        "ebs": {
                            "summary": "EBS Volumes Example",
                            "value": {
                                "status": "success",
                                "message": "Retrieved 25 EBS volumes",
                                "data": [
                                    {
                                        "VolumeId": "vol-1234567890abcdef0",
                                        "Size": 100,
                                        "VolumeType": "gp3",
                                        "State": "in-use",
                                        "Encrypted": True,
                                        "AvailabilityZone": "us-east-1a"
                                    }
                                ],
                                "metadata": {
                                    "total_count": 25,
                                    "service": "ebs",
                                    "account_id": "123456789012",
                                    "region": "us-east-1"
                                }
                            }
                        },
                        "efs": {
                            "summary": "EFS Filesystems Example",
                            "value": {
                                "status": "success",
                                "message": "Retrieved 3 EFS filesystems",
                                "data": [
                                    {
                                        "FileSystemId": "fs-1234567890abcdef0",
                                        "Name": "shared-storage",
                                        "PerformanceMode": "generalPurpose",
                                        "ThroughputMode": "bursting",
                                        "Encrypted": True,
                                        "LifeCycleState": "available"
                                    }
                                ],
                                "metadata": {
                                    "total_count": 3,
                                    "service": "efs",
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
async def list_storage_resources(
    request: Request,
    service: str,
    account_id: str = Query(..., description="AWS Account ID", example="123456789012"),
    region: str = Query("us-east-1", description="AWS Region", example="us-east-1")
):
    """List all resources for a specific storage service (s3, ebs, or efs)"""
    
    if service not in STORAGE_SERVICES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid service '{service}'. Supported services: {', '.join(STORAGE_SERVICES)}"
        )
    
    session = getattr(request.state, "session", None)
    if not session:
        raise HTTPException(status_code=401, detail="AWS session not found")
    
    try:
        if service == "s3":
            resources = list_s3_buckets(session, account_id, region)
            data = [bucket.dict() for bucket in resources]
        elif service == "ebs":
            resources = list_ebs_volumes(session, account_id, region)
            data = [volume.dict() for volume in resources]
        elif service == "efs":
            resources = list_efs_filesystems(session, account_id, region)
            data = [fs.dict() for fs in resources]
        
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
        logger.exception(f"Unexpected error in list_storage_resources for {service}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post(
    "/storage/{service}",
    response_model=StandardResponse,
    summary="Get detailed resource information for a storage service",
    description="Returns detailed information and security analysis for specified resources (S3 buckets, EBS volumes, or EFS filesystems)",
    responses={
        200: {
            "description": "Successful response",
            "content": {
                "application/json": {
                    "examples": {
                        "s3": {
                            "summary": "S3 Bucket Details Example",
                            "value": {
                                "status": "success",
                                "message": "Retrieved details for 1 s3 resources",
                                "data": [
                                    {
                                        "Name": "my-application-logs",
                                        "Region": "us-east-1",
                                        "Versioning": "Enabled",
                                        "Encryption": {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]},
                                        "Logging": True,
                                        "security_findings": [
                                            {
                                                "type": "security",
                                                "severity": "high",
                                                "message": "MFA Delete not enabled",
                                                "recommendation": "Enable MFA Delete for additional protection"
                                            }
                                        ],
                                        "recommendations": [
                                            {
                                                "type": "cost_optimization",
                                                "severity": "medium",
                                                "message": "No lifecycle policy configured",
                                                "recommendation": "Configure lifecycle policies to transition objects to cheaper storage"
                                            }
                                        ]
                                    }
                                ],
                                "metadata": {
                                    "requested_count": 1,
                                    "successful_count": 1,
                                    "failed_count": 0,
                                    "service": "s3",
                                    "account_id": "123456789012",
                                    "region": "us-east-1"
                                }
                            }
                        },
                        "ebs": {
                            "summary": "EBS Volume Details Example",
                            "value": {
                                "status": "success",
                                "message": "Retrieved details for 1 ebs resources",
                                "data": [
                                    {
                                        "VolumeId": "vol-1234567890abcdef0",
                                        "Size": 100,
                                        "VolumeType": "gp2",
                                        "State": "available",
                                        "Encrypted": False,
                                        "security_findings": [
                                            {
                                                "type": "security",
                                                "severity": "high",
                                                "message": "Volume is not encrypted"
                                            }
                                        ],
                                        "recommendations": [
                                            {
                                                "type": "cost_optimization",
                                                "severity": "high",
                                                "message": "Volume is not attached to any instance"
                                            },
                                            {
                                                "type": "performance",
                                                "severity": "low",
                                                "message": "Using older gp2 volume type"
                                            }
                                        ]
                                    }
                                ],
                                "metadata": {
                                    "requested_count": 1,
                                    "successful_count": 1,
                                    "failed_count": 0,
                                    "service": "ebs",
                                    "account_id": "123456789012",
                                    "region": "us-east-1"
                                }
                            }
                        },
                        "efs": {
                            "summary": "EFS Filesystem Details Example",
                            "value": {
                                "status": "success",
                                "message": "Retrieved details for 1 efs resources",
                                "data": [
                                    {
                                        "FileSystemId": "fs-1234567890abcdef0",
                                        "Name": "shared-storage",
                                        "PerformanceMode": "generalPurpose",
                                        "Encrypted": False,
                                        "security_findings": [
                                            {
                                                "type": "security",
                                                "severity": "high",
                                                "message": "Filesystem is not encrypted"
                                            }
                                        ],
                                        "recommendations": [
                                            {
                                                "type": "backup",
                                                "severity": "high",
                                                "message": "Automatic backups not enabled"
                                            },
                                            {
                                                "type": "availability",
                                                "severity": "medium",
                                                "message": "Filesystem has mount targets in less than 2 availability zones"
                                            }
                                        ]
                                    }
                                ],
                                "metadata": {
                                    "requested_count": 1,
                                    "successful_count": 1,
                                    "failed_count": 0,
                                    "service": "efs",
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
async def get_storage_details(
    request: Request,
    service: str,
    payload: ResourceIdsRequest = Body(...),
    account_id: str = Query(..., description="AWS Account ID"),
    region: str = Query("us-east-1", description="AWS Region")
):
    """Get detailed information for multiple resources of a specific storage service"""
    
    if service not in STORAGE_SERVICES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid service '{service}'. Supported services: {', '.join(STORAGE_SERVICES)}"
        )
    
    session = getattr(request.state, "session", None)
    if not session:
        raise HTTPException(status_code=401, detail="AWS session not found")
    
    try:
        details = []
        errors = []
        
        if service == "s3":
            s3_client = session.client("s3")
            for bucket_name in payload.resource_ids:
                try:
                    detail = analyze_s3_bucket(s3_client, bucket_name)
                    details.append(detail.dict())
                except HTTPException as he:
                    errors.append(f"{bucket_name}: {he.detail}")
                except Exception as e:
                    errors.append(f"{bucket_name}: {str(e)}")
        
        elif service == "ebs":
            ec2_client = session.client("ec2", region_name=region)
            for volume_id in payload.resource_ids:
                try:
                    detail = analyze_ebs_volume(ec2_client, volume_id)
                    details.append(detail.dict())
                except HTTPException as he:
                    errors.append(f"{volume_id}: {he.detail}")
                except Exception as e:
                    errors.append(f"{volume_id}: {str(e)}")
        
        elif service == "efs":
            efs_client = session.client("efs", region_name=region)
            for filesystem_id in payload.resource_ids:
                try:
                    detail = analyze_efs_filesystem(efs_client, filesystem_id)
                    details.append(detail.dict())
                except HTTPException as he:
                    errors.append(f"{filesystem_id}: {he.detail}")
                except Exception as e:
                    errors.append(f"{filesystem_id}: {str(e)}")
        
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
        logger.exception(f"Unexpected error in get_storage_details for {service}")
        raise HTTPException(status_code=500, detail=str(e))