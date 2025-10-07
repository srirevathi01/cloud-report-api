from fastapi import APIRouter, Request, HTTPException, Query
from pydantic import BaseModel
from botocore.exceptions import ClientError
from typing import Dict, Any, List
from datetime import datetime
import logging
import time

router = APIRouter()
logger = logging.getLogger(__name__)


STORAGE_SERVICES = ["s3", "ebs", "efs"]


CACHE: Dict[Any, Dict[str, Any]] = {}
CACHE_TTL = 300

def get_from_cache(account_id: str, region: str, service: str):
    key = (account_id, region, service)
    entry = CACHE.get(key)
    if entry and (time.time() - entry["timestamp"] < CACHE_TTL):
        return entry["data"]
    return None

def set_cache(account_id: str, region: str, service: str, data: Any):
    key = (account_id, region, service)
    CACHE[key] = {"data": data, "timestamp": time.time()}


# Models

class ResourceDetailRequest(BaseModel):
    resource_id: str

class StorageListResponse(BaseModel):
    account_id: str
    region: str
    s3: List[str] = []
    ebs: List[str] = []
    efs: List[str] = []

class ServiceListResponse(BaseModel):
    account_id: str
    region: str
    service: str
    resources: List[str] = []
    total: int

class Recommendation(BaseModel):
    type: str
    severity: str
    message: str

class S3Detail(BaseModel):
    name: str
    public_access_block: dict = {}
    encryption: dict = {}
    versioning: str
    logging: bool
    recommendations: List[Recommendation] = []

class EBSDetail(BaseModel):
    id: str
    size: int
    type: str
    state: str
    encrypted: bool
    recommendations: List[Recommendation] = []

class EFSDetail(BaseModel):
    id: str
    performance_mode: str
    encrypted: bool
    throughput_mode: str
    recommendations: List[Recommendation] = []

class ResourceDetailResponse(BaseModel):
    account_id: str
    region: str
    service: str
    resource: str
    details: dict

# Helper Functions

def list_s3_buckets(session, account_id: str, region: str) -> List[str]:
    cached = get_from_cache(account_id, region, "s3")
    if cached is not None:
        return cached

    s3 = session.client("s3")
    buckets = []
    try:
        for bucket in s3.list_buckets()["Buckets"]:
            try:
                location = s3.get_bucket_location(Bucket=bucket["Name"])
                bucket_region = location.get("LocationConstraint") or "us-east-1"
                if bucket_region == region:
                    buckets.append(bucket["Name"])
            except ClientError:
                continue
    except ClientError as e:
        logger.error(f"Error listing S3 buckets: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

    set_cache(account_id, region, "s3", buckets)
    return buckets

def list_ebs_volumes(session, account_id: str, region: str) -> List[str]:
    cached = get_from_cache(account_id, region, "ebs")
    if cached is not None:
        return cached

    ec2 = session.client("ec2", region_name=region)
    try:
        volumes = ec2.describe_volumes()["Volumes"]
        vol_ids = [vol["VolumeId"] for vol in volumes]
        set_cache(account_id, region, "ebs", vol_ids)
        return vol_ids
    except ClientError as e:
        logger.error(f"Error listing EBS volumes: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

def list_efs_filesystems(session, account_id: str, region: str) -> List[str]:
    cached = get_from_cache(account_id, region, "efs")
    if cached is not None:
        return cached

    efs = session.client("efs", region_name=region)
    try:
        filesystems = efs.describe_file_systems()["FileSystems"]
        fs_ids = [fs["FileSystemId"] for fs in filesystems]
        set_cache(account_id, region, "efs", fs_ids)
        return fs_ids
    except ClientError as e:
        logger.error(f"Error listing EFS filesystems: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

# Analysis Functions
def analyze_s3_bucket(s3_client, bucket_name: str) -> Dict[str, Any]:
    details = {"name": bucket_name, "recommendations": []}
    try:
        try:
            pab = s3_client.get_public_access_block(Bucket=bucket_name)
            details["public_access_block"] = pab["PublicAccessBlockConfiguration"]
        except ClientError:
            details["recommendations"].append({
                "type": "security",
                "severity": "critical",
                "message": "Public access block not configured"
            })
        try:
            enc = s3_client.get_bucket_encryption(Bucket=bucket_name)
            details["encryption"] = enc.get("ServerSideEncryptionConfiguration", {})
        except ClientError:
            details["recommendations"].append({
                "type": "security",
                "severity": "high",
                "message": "Bucket encryption not enabled"
            })
        ver = s3_client.get_bucket_versioning(Bucket=bucket_name)
        details["versioning"] = ver.get("Status", "Disabled")
        if details["versioning"] != "Enabled":
            details["recommendations"].append({
                "type": "data_protection",
                "severity": "medium",
                "message": "Versioning not enabled"
            })
        log = s3_client.get_bucket_logging(Bucket=bucket_name)
        details["logging"] = "LoggingEnabled" in log
        if "LoggingEnabled" not in log:
            details["recommendations"].append({
                "type": "monitoring",
                "severity": "medium",
                "message": "Server access logging not enabled"
            })
    except Exception as e:
        logger.error(f"Error analyzing S3 bucket {bucket_name}: {str(e)}")
    return details

def analyze_ebs_volume(ec2_client, volume_id: str) -> Dict[str, Any]:
    details = {"id": volume_id, "recommendations": []}
    try:
        vol = ec2_client.describe_volumes(VolumeIds=[volume_id])["Volumes"][0]
        details.update({
            "size": vol["Size"],
            "type": vol["VolumeType"],
            "encrypted": vol["Encrypted"],
            "state": vol["State"],
        })
        if not vol["Encrypted"]:
            details["recommendations"].append({
                "type": "security",
                "severity": "high",
                "message": "Volume not encrypted"
            })
        if not vol["Attachments"]:
            details["recommendations"].append({
                "type": "cost_optimization",
                "severity": "high",
                "message": "Unattached volume"
            })
        if vol["VolumeType"] == "gp2":
            details["recommendations"].append({
                "type": "performance",
                "severity": "low",
                "message": "Consider migrating to gp3"
            })
    except Exception as e:
        logger.error(f"Error analyzing EBS volume {volume_id}: {str(e)}")
    return details

def analyze_efs_filesystem(efs_client, fs_id: str) -> Dict[str, Any]:
    details = {"id": fs_id, "recommendations": []}
    try:
        fs = efs_client.describe_file_systems(FileSystemId=fs_id)["FileSystems"][0]
        details.update({
            "performance_mode": fs["PerformanceMode"],
            "encrypted": fs["Encrypted"],
            "throughput_mode": fs["ThroughputMode"],
        })
        if not fs["Encrypted"]:
            details["recommendations"].append({
                "type": "security",
                "severity": "high",
                "message": "Filesystem not encrypted"
            })
        if fs["PerformanceMode"] == "generalPurpose":
            details["recommendations"].append({
                "type": "performance",
                "severity": "low",
                "message": "Consider maxIO for throughput workloads"
            })
        if not fs.get("LifecyclePolicies"):
            details["recommendations"].append({
                "type": "cost_optimization",
                "severity": "medium",
                "message": "No lifecycle policy configured"
            })
    except Exception as e:
        logger.error(f"Error analyzing EFS filesystem {fs_id}: {str(e)}")
    return details

# Routes

@router.get("/storage", response_model=StorageListResponse, summary="List all storage resources")
async def list_all_storage(
    request: Request,
    account_id: str = Query(..., description="AWS account ID"),
    region: str = Query("us-east-1", description="AWS region")
):
    session = getattr(request.state, "session", None)
    if not session:
        raise HTTPException(401, "AWS session not found")

    return StorageListResponse(
        account_id=account_id,
        region=region,
        s3=list_s3_buckets(session, account_id, region),
        ebs=list_ebs_volumes(session, account_id, region),
        efs=list_efs_filesystems(session, account_id, region)
    )

@router.get("/storage/{service}", response_model=ServiceListResponse, summary="List resources for a specific service")
async def list_service_storage(
    service: str,
    request: Request,
    account_id: str = Query(..., description="AWS account ID"),
    region: str = Query("us-east-1", description="AWS region")
):
    if service not in STORAGE_SERVICES:
        raise HTTPException(404, f"Service {service} not supported")
    session = getattr(request.state, "session", None)
    if not session:
        raise HTTPException(401, "AWS session not found")

    if service == "s3":
        resources = list_s3_buckets(session, account_id, region)
    elif service == "ebs":
        resources = list_ebs_volumes(session, account_id, region)
    elif service == "efs":
        resources = list_efs_filesystems(session, account_id, region)

    return ServiceListResponse(
        account_id=account_id,
        region=region,
        service=service,
        resources=resources,
        total=len(resources)
    )

@router.post("/storage/{service}/detail", response_model=ResourceDetailResponse, summary="Get detailed resource info")
async def get_storage_detail(
    service: str,
    request: Request,
    payload: ResourceDetailRequest,
    account_id: str = Query(..., description="AWS account ID"),
    region: str = Query("us-east-1", description="AWS region")
):
    if service not in STORAGE_SERVICES:
        raise HTTPException(404, f"Service {service} not supported")
    session = getattr(request.state, "session", None)
    if not session:
        raise HTTPException(401, "AWS session not found")

    # Check if resource exists in the region
    if service == "s3":
        s3 = session.client("s3", region_name=region)
        buckets = list_s3_buckets(session, account_id, region)
        if payload.resource_id not in buckets:
            raise HTTPException(404, f"S3 bucket '{payload.resource_id}' not found in region {region}")
        details = analyze_s3_bucket(s3, payload.resource_id)

    elif service == "ebs":
        ec2 = session.client("ec2", region_name=region)
        volumes = list_ebs_volumes(session, account_id, region)
        if payload.resource_id not in volumes:
            raise HTTPException(404, f"EBS volume '{payload.resource_id}' not found in region {region}")
        details = analyze_ebs_volume(ec2, payload.resource_id)

    elif service == "efs":
        efs = session.client("efs", region_name=region)
        filesystems = list_efs_filesystems(session, account_id, region)
        if payload.resource_id not in filesystems:
            raise HTTPException(404, f"EFS filesystem '{payload.resource_id}' not found in region {region}")
        details = analyze_efs_filesystem(efs, payload.resource_id)

    return ResourceDetailResponse(
        account_id=account_id,
        region=region,
        service=service,
        resource=payload.resource_id,
        details=details
    )
