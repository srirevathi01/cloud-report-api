from fastapi import APIRouter, Request, HTTPException, Query
from pydantic import BaseModel, Field
from botocore.exceptions import ClientError
from typing import Dict, Any, List
import logging
import time

router = APIRouter()
logger = logging.getLogger(__name__)

# Database services
DATABASE_SERVICES = ["aurora", "rds", "dynamodb", "elasticache"]

# Cache Implementation
CACHE_DB: Dict[Any, Dict[str, Any]] = {}
CACHE_TTL = 300

def get_db_cache(account_id: str, region: str, service: str):
    key = (account_id, region, service)
    entry = CACHE_DB.get(key)
    if entry and (time.time() - entry["timestamp"] < CACHE_TTL):
        return entry["data"]
    return None

def set_db_cache(account_id: str, region: str, service: str, data: Any):
    key = (account_id, region, service)
    CACHE_DB[key] = {"data": data, "timestamp": time.time()}

# Pydantic Models
class ResourceDetailRequest(BaseModel):
    resource_id: str

class DatabaseListResponse(BaseModel):
    account_id: str
    region: str
    aurora: List[str] = Field(default_factory=list)
    rds: List[str] = Field(default_factory=list)
    dynamodb: List[str] = Field(default_factory=list)
    elasticache: List[str] = Field(default_factory=list)

class ServiceListResponse(BaseModel):
    account_id: str
    region: str
    service: str
    resources: List[str] = Field(default_factory=list)
    total: int

class Recommendation(BaseModel):
    type: str
    severity: str
    message: str

class ResourceDetailResponse(BaseModel):
    account_id: str
    region: str
    service: str
    resource: str
    details: dict

# Helper Functions
def list_aurora_clusters(session, account_id: str, region: str) -> List[str]:
    cached = get_db_cache(account_id, region, "aurora")
    if cached is not None:
        return cached
    rds = session.client("rds", region_name=region)
    clusters = []
    try:
        paginator = rds.get_paginator("describe_db_clusters")
        for page in paginator.paginate():
            for c in page.get("DBClusters", []):
                clusters.append(c["DBClusterIdentifier"])
    except ClientError as e:
        logger.error(f"Error listing Aurora clusters: {str(e)}")
        raise HTTPException(500, detail=str(e))
    set_db_cache(account_id, region, "aurora", clusters)
    return clusters

def list_rds_instances(session, account_id: str, region: str) -> List[str]:
    cached = get_db_cache(account_id, region, "rds")
    if cached is not None:
        return cached
    rds = session.client("rds", region_name=region)
    instances = []
    try:
        paginator = rds.get_paginator("describe_db_instances")
        for page in paginator.paginate():
            for i in page.get("DBInstances", []):
                instances.append(i["DBInstanceIdentifier"])
    except ClientError as e:
        logger.error(f"Error listing RDS instances: {str(e)}")
        raise HTTPException(500, detail=str(e))
    set_db_cache(account_id, region, "rds", instances)
    return instances

def list_dynamodb_tables(session, account_id: str, region: str) -> List[str]:
    cached = get_db_cache(account_id, region, "dynamodb")
    if cached is not None:
        return cached
    dynamodb = session.client("dynamodb", region_name=region)
    tables = []
    try:
        paginator = dynamodb.get_paginator("list_tables")
        for page in paginator.paginate():
            tables.extend(page.get("TableNames", []))
    except ClientError as e:
        logger.error(f"Error listing DynamoDB tables: {str(e)}")
        raise HTTPException(500, detail=str(e))
    set_db_cache(account_id, region, "dynamodb", tables)
    return tables

def list_elasticache_clusters(session, account_id: str, region: str) -> List[str]:
    cached = get_db_cache(account_id, region, "elasticache")
    if cached is not None:
        return cached
    ec = session.client("elasticache", region_name=region)
    clusters = []
    try:
        paginator = ec.get_paginator("describe_cache_clusters")
        for page in paginator.paginate(ShowCacheNodeInfo=True):
            for c in page.get("CacheClusters", []):
                clusters.append(c["CacheClusterId"])
    except ClientError as e:
        logger.error(f"Error listing ElastiCache clusters: {str(e)}")
        raise HTTPException(500, detail=str(e))
    set_db_cache(account_id, region, "elasticache", clusters)
    return clusters

# Analysis Functions with Security Recommendations
def analyze_aurora_cluster(rds_client, cluster_id: str) -> Dict[str, Any]:
    details = {"id": cluster_id, "recommendations": []}
    try:
        cluster = rds_client.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]
        details.update({
            "engine": cluster["Engine"],
            "status": cluster["Status"],
            "encrypted": cluster["StorageEncrypted"],
            "publicly_accessible": cluster.get("PubliclyAccessible", False),
            "multi_az": cluster.get("MultiAZ", False),
            "backup_retention": cluster.get("BackupRetentionPeriod", 0),
            "iam_auth_enabled": cluster.get("IAMDatabaseAuthenticationEnabled", False)
        })
        # Recommendations
        if not details["encrypted"]:
            details["recommendations"].append({"type":"security","severity":"high","message":"Cluster not encrypted"})
        if details["publicly_accessible"]:
            details["recommendations"].append({"type":"security","severity":"high","message":"Cluster is publicly accessible"})
        if details["backup_retention"] == 0:
            details["recommendations"].append({"type":"backup","severity":"medium","message":"Backup retention is 0"})
        if not details["multi_az"]:
            details["recommendations"].append({"type":"high_availability","severity":"medium","message":"Cluster is not Multi-AZ"})
        if not details["iam_auth_enabled"]:
            details["recommendations"].append({"type":"security","severity":"low","message":"IAM auth not enabled"})
    except ClientError:
        raise HTTPException(404, f"Aurora cluster '{cluster_id}' not found")
    return details

def analyze_rds_instance(rds_client, instance_id: str) -> Dict[str, Any]:
    details = {"id": instance_id, "recommendations": []}
    try:
        inst = rds_client.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0]
        details.update({
            "engine": inst["Engine"],
            "status": inst["DBInstanceStatus"],
            "encrypted": inst["StorageEncrypted"],
            "publicly_accessible": inst.get("PubliclyAccessible", False),
            "multi_az": inst.get("MultiAZ", False),
            "backup_retention": inst.get("BackupRetentionPeriod", 0),
            "iam_auth_enabled": inst.get("IAMDatabaseAuthenticationEnabled", False)
        })
        if not details["encrypted"]:
            details["recommendations"].append({"type":"security","severity":"high","message":"Instance not encrypted"})
        if details["publicly_accessible"]:
            details["recommendations"].append({"type":"security","severity":"high","message":"Instance is publicly accessible"})
        if details["backup_retention"] == 0:
            details["recommendations"].append({"type":"backup","severity":"medium","message":"Backup retention is 0"})
        if not details["multi_az"]:
            details["recommendations"].append({"type":"high_availability","severity":"medium","message":"Instance is not Multi-AZ"})
        if not details["iam_auth_enabled"]:
            details["recommendations"].append({"type":"security","severity":"low","message":"IAM auth not enabled"})
    except ClientError:
        raise HTTPException(404, f"RDS instance '{instance_id}' not found")
    return details

def analyze_dynamodb_table(ddb_client, table_name: str) -> Dict[str, Any]:
    details = {"table_name": table_name, "recommendations": []}
    try:
        table = ddb_client.describe_table(TableName=table_name)["Table"]
        encrypted = table.get("SSEDescription", {}).get("Status") == "ENABLED"
        pitr = table.get("PointInTimeRecoveryDescription", {}).get("PointInTimeRecoveryStatus") == "ENABLED"
        details.update({
            "status": table["TableStatus"],
            "billing_mode": table.get("BillingModeSummary", {}).get("BillingMode", "PROVISIONED"),
            "encrypted": encrypted,
            "pitr_enabled": pitr
        })
        if not encrypted:
            details["recommendations"].append({"type":"security","severity":"high","message":"Table not encrypted"})
        if not pitr:
            details["recommendations"].append({"type":"backup","severity":"medium","message":"Point-in-time recovery not enabled"})
    except ClientError:
        raise HTTPException(404, f"DynamoDB table '{table_name}' not found")
    return details

def analyze_elasticache_cluster(ec_client, cluster_id: str) -> Dict[str, Any]:
    details = {"id": cluster_id, "recommendations": []}
    try:
        cluster = ec_client.describe_cache_clusters(CacheClusterId=cluster_id, ShowCacheNodeInfo=True)["CacheClusters"][0]
        in_transit_encryption = cluster.get("TransitEncryptionEnabled", False)
        at_rest_encryption = cluster.get("AtRestEncryptionEnabled", False)
        auth_token_enabled = cluster.get("AuthTokenEnabled", False)
        publicly_accessible = cluster.get("CacheClusterStatus") == "available" and cluster.get("CacheSubnetGroupName") == "default"
        details.update({
            "engine": cluster["Engine"],
            "node_type": cluster["CacheNodeType"],
            "status": cluster["CacheClusterStatus"],
            "in_transit_encryption": in_transit_encryption,
            "at_rest_encryption": at_rest_encryption,
            "auth_token_enabled": auth_token_enabled,
            "publicly_accessible": publicly_accessible
        })
        if not in_transit_encryption or not at_rest_encryption:
            details["recommendations"].append({"type":"security","severity":"high","message":"Encryption not enabled"})
        if not auth_token_enabled:
            details["recommendations"].append({"type":"security","severity":"high","message":"Auth token not enabled"})
        if publicly_accessible:
            details["recommendations"].append({"type":"security","severity":"high","message":"Cluster is publicly accessible"})
    except ClientError:
        raise HTTPException(404, f"ElastiCache cluster '{cluster_id}' not found")
    return details

# ------------------------
# Routes
# ------------------------
@router.get("/database", response_model=DatabaseListResponse, summary="List all database resources")
async def list_all_databases(
    request: Request,
    account_id: str = Query(..., description="AWS account ID"),
    region: str = Query("us-east-1", description="AWS region")
):
    session = getattr(request.state, "session", None)
    if not session:
        raise HTTPException(401, "AWS session not found")
    return DatabaseListResponse(
        account_id=account_id,
        region=region,
        aurora=list_aurora_clusters(session, account_id, region),
        rds=list_rds_instances(session, account_id, region),
        dynamodb=list_dynamodb_tables(session, account_id, region),
        elasticache=list_elasticache_clusters(session, account_id, region)
    )

@router.get("/database/{service}", response_model=ServiceListResponse, summary="List resources for a specific database service")
async def list_database_service(
    service: str,
    request: Request,
    account_id: str = Query(..., description="AWS account ID"),
    region: str = Query("us-east-1", description="AWS region")
):
    if service not in DATABASE_SERVICES:
        raise HTTPException(404, f"Service {service} not supported")
    session = getattr(request.state, "session", None)
    if not session:
        raise HTTPException(401, "AWS session not found")

    if service == "aurora":
        resources = list_aurora_clusters(session, account_id, region)
    elif service == "rds":
        resources = list_rds_instances(session, account_id, region)
    elif service == "dynamodb":
        resources = list_dynamodb_tables(session, account_id, region)
    elif service == "elasticache":
        resources = list_elasticache_clusters(session, account_id, region)

    return ServiceListResponse(
        account_id=account_id,
        region=region,
        service=service,
        resources=resources,
        total=len(resources)
    )

@router.post("/database/{service}/detail", response_model=ResourceDetailResponse, summary="Get detailed database resource info")
async def get_database_detail(
    service: str,
    request: Request,
    payload: ResourceDetailRequest,
    account_id: str = Query(..., description="AWS account ID"),
    region: str = Query("us-east-1", description="AWS region")
):
    if service not in DATABASE_SERVICES:
        raise HTTPException(404, f"Service {service} not supported")
    session = getattr(request.state, "session", None)
    if not session:
        raise HTTPException(401, "AWS session not found")

    # Verify existence & analyze
    if service == "aurora":
        clusters = list_aurora_clusters(session, account_id, region)
        if payload.resource_id not in clusters:
            raise HTTPException(404, f"Aurora cluster '{payload.resource_id}' not found in region {region}")
        rds = session.client("rds", region_name=region)
        details = analyze_aurora_cluster(rds, payload.resource_id)
    elif service == "rds":
        instances = list_rds_instances(session, account_id, region)
        if payload.resource_id not in instances:
            raise HTTPException(404, f"RDS instance '{payload.resource_id}' not found in region {region}")
        rds = session.client("rds", region_name=region)
        details = analyze_rds_instance(rds, payload.resource_id)
    elif service == "dynamodb":
        tables = list_dynamodb_tables(session, account_id, region)
        if payload.resource_id not in tables:
            raise HTTPException(404, f"DynamoDB table '{payload.resource_id}' not found in region {region}")
        ddb = session.client("dynamodb", region_name=region)
        details = analyze_dynamodb_table(ddb, payload.resource_id)
    elif service == "elasticache":
        clusters = list_elasticache_clusters(session, account_id, region)
        if payload.resource_id not in clusters:
            raise HTTPException(404, f"ElastiCache cluster '{payload.resource_id}' not found in region {region}")
        ec = session.client("elasticache", region_name=region)
        details = analyze_elasticache_cluster(ec, payload.resource_id)

    return ResourceDetailResponse(
        account_id=account_id,
        region=region,
        service=service,
        resource=payload.resource_id,
        details=details
    )
