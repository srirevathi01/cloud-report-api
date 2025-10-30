"""
AWS Database Services Controller
Handles RDS, DynamoDB, Aurora, and ElastiCache resources with comprehensive security and performance recommendations
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
DATABASE_SERVICES = ["rds", "dynamodb", "aurora", "elasticache"]
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
        example=["my-database-instance", "my-cluster-name"]
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


class RDSInstanceBasic(BaseModel):
    """Basic RDS instance information"""
    DBInstanceIdentifier: str
    DBInstanceClass: str
    Engine: str
    DBInstanceStatus: str
    AvailabilityZone: Optional[str] = None
    MultiAZ: bool = False


class RDSInstanceDetail(BaseModel):
    """Detailed RDS instance information with security analysis"""
    DBInstanceIdentifier: str
    DBInstanceClass: str
    Engine: str
    EngineVersion: str
    DBInstanceStatus: str
    MasterUsername: str
    Endpoint: Optional[Dict[str, Any]] = None
    AllocatedStorage: int
    StorageType: str
    StorageEncrypted: bool
    KmsKeyId: Optional[str] = None
    AvailabilityZone: str
    MultiAZ: bool
    PubliclyAccessible: bool
    VpcSecurityGroups: List[Dict[str, str]] = []
    DBSubnetGroup: Optional[Dict[str, Any]] = None
    BackupRetentionPeriod: int
    PreferredBackupWindow: Optional[str] = None
    PreferredMaintenanceWindow: Optional[str] = None
    LatestRestorableTime: Optional[str] = None
    AutoMinorVersionUpgrade: bool
    IAMDatabaseAuthenticationEnabled: bool
    PerformanceInsightsEnabled: bool = False
    DeletionProtection: bool = False
    EnabledCloudwatchLogsExports: List[str] = []
    Tags: List[Dict[str, str]] = []
    recommendations: List[Dict[str, Any]] = []
    security_findings: List[Dict[str, Any]] = []


class AuroraClusterBasic(BaseModel):
    """Basic Aurora cluster information"""
    DBClusterIdentifier: str
    Engine: str
    Status: str
    MultiAZ: bool = False
    ClusterMembers: int = 0


class AuroraClusterDetail(BaseModel):
    """Detailed Aurora cluster information with security analysis"""
    DBClusterIdentifier: str
    DBClusterArn: str
    Engine: str
    EngineVersion: str
    Status: str
    Endpoint: Optional[str] = None
    ReaderEndpoint: Optional[str] = None
    MultiAZ: bool
    StorageEncrypted: bool
    KmsKeyId: Optional[str] = None
    AvailabilityZones: List[str] = []
    BackupRetentionPeriod: int
    PreferredBackupWindow: Optional[str] = None
    PreferredMaintenanceWindow: Optional[str] = None
    VpcSecurityGroups: List[Dict[str, str]] = []
    DBSubnetGroup: Optional[str] = None
    IAMDatabaseAuthenticationEnabled: bool
    DeletionProtection: bool = False
    EnabledCloudwatchLogsExports: List[str] = []
    ClusterMembers: List[Dict[str, Any]] = []
    Tags: List[Dict[str, str]] = []
    recommendations: List[Dict[str, Any]] = []
    security_findings: List[Dict[str, Any]] = []


class DynamoDBTableBasic(BaseModel):
    """Basic DynamoDB table information"""
    TableName: str
    TableStatus: str
    CreationDateTime: Optional[str] = None
    ItemCount: Optional[int] = None
    TableSizeBytes: Optional[int] = None


class DynamoDBTableDetail(BaseModel):
    """Detailed DynamoDB table information with security analysis"""
    TableName: str
    TableArn: str
    TableStatus: str
    CreationDateTime: str
    KeySchema: List[Dict[str, str]] = []
    AttributeDefinitions: List[Dict[str, str]] = []
    BillingMode: str
    ProvisionedThroughput: Optional[Dict[str, Any]] = None
    ItemCount: int
    TableSizeBytes: int
    SSEDescription: Optional[Dict[str, Any]] = None
    StreamSpecification: Optional[Dict[str, Any]] = None
    LatestStreamArn: Optional[str] = None
    PointInTimeRecoveryEnabled: bool = False
    GlobalSecondaryIndexes: List[Dict[str, Any]] = []
    LocalSecondaryIndexes: List[Dict[str, Any]] = []
    Tags: List[Dict[str, str]] = []
    BackupArn: Optional[str] = None
    recommendations: List[Dict[str, Any]] = []
    security_findings: List[Dict[str, Any]] = []


class ElastiCacheClusterBasic(BaseModel):
    """Basic ElastiCache cluster information"""
    CacheClusterId: str
    CacheNodeType: str
    Engine: str
    CacheClusterStatus: str
    NumCacheNodes: int


class ElastiCacheClusterDetail(BaseModel):
    """Detailed ElastiCache cluster information with security analysis"""
    CacheClusterId: str
    CacheClusterArn: Optional[str] = None
    Engine: str
    EngineVersion: str
    CacheClusterStatus: str
    CacheNodeType: str
    NumCacheNodes: int
    PreferredAvailabilityZone: Optional[str] = None
    CacheClusterCreateTime: Optional[str] = None
    PreferredMaintenanceWindow: Optional[str] = None
    CacheSubnetGroupName: Optional[str] = None
    SecurityGroups: List[Dict[str, str]] = []
    AtRestEncryptionEnabled: bool = False
    TransitEncryptionEnabled: bool = False
    AuthTokenEnabled: bool = False
    SnapshotRetentionLimit: int = 0
    SnapshotWindow: Optional[str] = None
    AutoMinorVersionUpgrade: bool = True
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
        elif error_code in ["DBInstanceNotFoundFault", "DBClusterNotFoundFault", "ResourceNotFoundException"]:
            status_code = 404
        
        return HTTPException(status_code=status_code, detail=f"{error_code}: {error_msg}")
    else:
        logger.error(f"Unexpected error in {context}: {str(e)}")
        return HTTPException(status_code=500, detail=str(e))


# ============================================================================
# RDS FUNCTIONS
# ============================================================================

def list_rds_instances(session, account_id: str, region: str) -> List[RDSInstanceBasic]:
    """List all RDS instances (excluding Aurora) in a region using paginator"""
    cached = get_cache(account_id, region, "rds", "instances")
    if cached:
        return cached
    
    try:
        rds_client = session.client("rds", region_name=region)
        instances = []
        
        paginator = rds_client.get_paginator("describe_db_instances")
        for page in paginator.paginate():
            for instance in page.get("DBInstances", []):
                # Exclude Aurora instances (they're handled separately)
                if not instance.get("Engine", "").startswith("aurora"):
                    instances.append(RDSInstanceBasic(
                        DBInstanceIdentifier=instance["DBInstanceIdentifier"],
                        DBInstanceClass=instance["DBInstanceClass"],
                        Engine=instance["Engine"],
                        DBInstanceStatus=instance["DBInstanceStatus"],
                        AvailabilityZone=instance.get("AvailabilityZone"),
                        MultiAZ=instance.get("MultiAZ", False)
                    ))
        
        set_cache(account_id, region, "rds", "instances", instances)
        return instances
        
    except (ClientError, BotoCoreError) as e:
        raise handle_aws_error(e, "list_rds_instances")


def analyze_rds_instance(rds_client, instance_id: str) -> RDSInstanceDetail:
    """Get detailed RDS instance information with security analysis"""
    try:
        response = rds_client.describe_db_instances(DBInstanceIdentifier=instance_id)
        
        if not response["DBInstances"]:
            raise HTTPException(status_code=404, detail=f"RDS instance {instance_id} not found")
        
        instance = response["DBInstances"][0]
        
        # Get tags
        tags = []
        try:
            tags_response = rds_client.list_tags_for_resource(ResourceName=instance["DBInstanceArn"])
            tags = [{"Key": tag["Key"], "Value": tag["Value"]} for tag in tags_response.get("TagList", [])]
        except ClientError:
            pass
        
        # Build detailed instance info
        detail = RDSInstanceDetail(
            DBInstanceIdentifier=instance["DBInstanceIdentifier"],
            DBInstanceClass=instance["DBInstanceClass"],
            Engine=instance["Engine"],
            EngineVersion=instance["EngineVersion"],
            DBInstanceStatus=instance["DBInstanceStatus"],
            MasterUsername=instance["MasterUsername"],
            Endpoint=instance.get("Endpoint"),
            AllocatedStorage=instance["AllocatedStorage"],
            StorageType=instance.get("StorageType", "gp2"),
            StorageEncrypted=instance.get("StorageEncrypted", False),
            KmsKeyId=instance.get("KmsKeyId"),
            AvailabilityZone=instance.get("AvailabilityZone", ""),
            MultiAZ=instance.get("MultiAZ", False),
            PubliclyAccessible=instance.get("PubliclyAccessible", False),
            VpcSecurityGroups=[
                {"VpcSecurityGroupId": sg["VpcSecurityGroupId"], "Status": sg["Status"]}
                for sg in instance.get("VpcSecurityGroups", [])
            ],
            DBSubnetGroup=instance.get("DBSubnetGroup"),
            BackupRetentionPeriod=instance.get("BackupRetentionPeriod", 0),
            PreferredBackupWindow=instance.get("PreferredBackupWindow"),
            PreferredMaintenanceWindow=instance.get("PreferredMaintenanceWindow"),
            LatestRestorableTime=instance.get("LatestRestorableTime").isoformat() if instance.get("LatestRestorableTime") else None,
            AutoMinorVersionUpgrade=instance.get("AutoMinorVersionUpgrade", False),
            IAMDatabaseAuthenticationEnabled=instance.get("IAMDatabaseAuthenticationEnabled", False),
            PerformanceInsightsEnabled=instance.get("PerformanceInsightsEnabled", False),
            DeletionProtection=instance.get("DeletionProtection", False),
            EnabledCloudwatchLogsExports=instance.get("EnabledCloudwatchLogsExports", []),
            Tags=tags,
            recommendations=[],
            security_findings=[]
        )
        
        # Security Analysis
        if not detail.StorageEncrypted:
            detail.security_findings.append({
                "type": "security",
                "severity": "high",
                "message": "Storage encryption not enabled",
                "recommendation": "Enable encryption at rest for data protection"
            })
        
        if detail.PubliclyAccessible:
            detail.security_findings.append({
                "type": "security",
                "severity": "critical",
                "message": "Database is publicly accessible",
                "recommendation": "Disable public accessibility and use VPN/VPC peering for access"
            })
        
        if not detail.IAMDatabaseAuthenticationEnabled:
            detail.recommendations.append({
                "type": "security",
                "severity": "medium",
                "message": "IAM database authentication not enabled",
                "recommendation": "Enable IAM authentication for centralized access control"
            })
        
        if detail.BackupRetentionPeriod == 0:
            detail.security_findings.append({
                "type": "backup",
                "severity": "high",
                "message": "Automated backups disabled (retention period is 0)",
                "recommendation": "Enable automated backups with minimum 7-day retention"
            })
        elif detail.BackupRetentionPeriod < 7:
            detail.recommendations.append({
                "type": "backup",
                "severity": "medium",
                "message": f"Backup retention period is only {detail.BackupRetentionPeriod} days",
                "recommendation": "Consider increasing retention to at least 7 days"
            })
        
        if not detail.MultiAZ:
            detail.recommendations.append({
                "type": "availability",
                "severity": "high",
                "message": "Multi-AZ deployment not enabled",
                "recommendation": "Enable Multi-AZ for high availability and automatic failover"
            })
        
        if not detail.PerformanceInsightsEnabled:
            detail.recommendations.append({
                "type": "monitoring",
                "severity": "low",
                "message": "Performance Insights not enabled",
                "recommendation": "Enable Performance Insights for advanced monitoring and troubleshooting"
            })
        
        if not detail.DeletionProtection:
            detail.recommendations.append({
                "type": "data_protection",
                "severity": "medium",
                "message": "Deletion protection not enabled",
                "recommendation": "Enable deletion protection to prevent accidental deletion"
            })
        
        if not detail.EnabledCloudwatchLogsExports:
            detail.recommendations.append({
                "type": "monitoring",
                "severity": "medium",
                "message": "CloudWatch Logs export not configured",
                "recommendation": "Export logs to CloudWatch for centralized monitoring and analysis"
            })
        
        if not detail.AutoMinorVersionUpgrade:
            detail.recommendations.append({
                "type": "maintenance",
                "severity": "low",
                "message": "Automatic minor version upgrade disabled",
                "recommendation": "Enable auto minor version upgrades for security patches"
            })
        
        # Check for old storage type
        if detail.StorageType == "gp2":
            detail.recommendations.append({
                "type": "performance",
                "severity": "low",
                "message": "Using older gp2 storage type",
                "recommendation": "Consider migrating to gp3 for better performance and lower cost"
            })
        
        return detail
        
    except ClientError as e:
        raise handle_aws_error(e, f"analyze_rds_instance:{instance_id}")


# ============================================================================
# AURORA FUNCTIONS
# ============================================================================

def list_aurora_clusters(session, account_id: str, region: str) -> List[AuroraClusterBasic]:
    """List all Aurora clusters in a region using paginator"""
    cached = get_cache(account_id, region, "aurora", "clusters")
    if cached:
        return cached
    
    try:
        rds_client = session.client("rds", region_name=region)
        clusters = []
        
        paginator = rds_client.get_paginator("describe_db_clusters")
        for page in paginator.paginate():
            for cluster in page.get("DBClusters", []):
                # Only include Aurora clusters
                if cluster.get("Engine", "").startswith("aurora"):
                    clusters.append(AuroraClusterBasic(
                        DBClusterIdentifier=cluster["DBClusterIdentifier"],
                        Engine=cluster["Engine"],
                        Status=cluster["Status"],
                        MultiAZ=cluster.get("MultiAZ", False),
                        ClusterMembers=len(cluster.get("DBClusterMembers", []))
                    ))
        
        set_cache(account_id, region, "aurora", "clusters", clusters)
        return clusters
        
    except (ClientError, BotoCoreError) as e:
        raise handle_aws_error(e, "list_aurora_clusters")


def analyze_aurora_cluster(rds_client, cluster_id: str) -> AuroraClusterDetail:
    """Get detailed Aurora cluster information with security analysis"""
    try:
        response = rds_client.describe_db_clusters(DBClusterIdentifier=cluster_id)
        
        if not response["DBClusters"]:
            raise HTTPException(status_code=404, detail=f"Aurora cluster {cluster_id} not found")
        
        cluster = response["DBClusters"][0]
        
        # Get tags
        tags = []
        try:
            tags_response = rds_client.list_tags_for_resource(ResourceName=cluster["DBClusterArn"])
            tags = [{"Key": tag["Key"], "Value": tag["Value"]} for tag in tags_response.get("TagList", [])]
        except ClientError:
            pass
        
        # Build detailed cluster info
        detail = AuroraClusterDetail(
            DBClusterIdentifier=cluster["DBClusterIdentifier"],
            DBClusterArn=cluster["DBClusterArn"],
            Engine=cluster["Engine"],
            EngineVersion=cluster["EngineVersion"],
            Status=cluster["Status"],
            Endpoint=cluster.get("Endpoint"),
            ReaderEndpoint=cluster.get("ReaderEndpoint"),
            MultiAZ=cluster.get("MultiAZ", False),
            StorageEncrypted=cluster.get("StorageEncrypted", False),
            KmsKeyId=cluster.get("KmsKeyId"),
            AvailabilityZones=cluster.get("AvailabilityZones", []),
            BackupRetentionPeriod=cluster.get("BackupRetentionPeriod", 0),
            PreferredBackupWindow=cluster.get("PreferredBackupWindow"),
            PreferredMaintenanceWindow=cluster.get("PreferredMaintenanceWindow"),
            VpcSecurityGroups=[
                {"VpcSecurityGroupId": sg["VpcSecurityGroupId"], "Status": sg["Status"]}
                for sg in cluster.get("VpcSecurityGroups", [])
            ],
            DBSubnetGroup=cluster.get("DBSubnetGroup"),
            IAMDatabaseAuthenticationEnabled=cluster.get("IAMDatabaseAuthenticationEnabled", False),
            DeletionProtection=cluster.get("DeletionProtection", False),
            EnabledCloudwatchLogsExports=cluster.get("EnabledCloudwatchLogsExports", []),
            ClusterMembers=cluster.get("DBClusterMembers", []),
            Tags=tags,
            recommendations=[],
            security_findings=[]
        )
        
        # Security Analysis
        if not detail.StorageEncrypted:
            detail.security_findings.append({
                "type": "security",
                "severity": "high",
                "message": "Storage encryption not enabled",
                "recommendation": "Enable encryption at rest for data protection"
            })
        
        if not detail.IAMDatabaseAuthenticationEnabled:
            detail.recommendations.append({
                "type": "security",
                "severity": "medium",
                "message": "IAM database authentication not enabled",
                "recommendation": "Enable IAM authentication for centralized access control"
            })
        
        if detail.BackupRetentionPeriod == 0:
            detail.security_findings.append({
                "type": "backup",
                "severity": "high",
                "message": "Automated backups disabled (retention period is 0)",
                "recommendation": "Enable automated backups with minimum 7-day retention"
            })
        elif detail.BackupRetentionPeriod < 7:
            detail.recommendations.append({
                "type": "backup",
                "severity": "medium",
                "message": f"Backup retention period is only {detail.BackupRetentionPeriod} days",
                "recommendation": "Consider increasing retention to at least 7 days"
            })
        
        if len(detail.AvailabilityZones) < 2:
            detail.recommendations.append({
                "type": "availability",
                "severity": "high",
                "message": "Cluster not deployed across multiple availability zones",
                "recommendation": "Deploy across at least 2 AZs for high availability"
            })
        
        if len(detail.ClusterMembers) < 2:
            detail.recommendations.append({
                "type": "availability",
                "severity": "medium",
                "message": "Cluster has less than 2 instances",
                "recommendation": "Add read replicas for high availability and read scaling"
            })
        
        if not detail.DeletionProtection:
            detail.recommendations.append({
                "type": "data_protection",
                "severity": "medium",
                "message": "Deletion protection not enabled",
                "recommendation": "Enable deletion protection to prevent accidental deletion"
            })
        
        if not detail.EnabledCloudwatchLogsExports:
            detail.recommendations.append({
                "type": "monitoring",
                "severity": "medium",
                "message": "CloudWatch Logs export not configured",
                "recommendation": "Export logs to CloudWatch for centralized monitoring and analysis"
            })
        
        return detail
        
    except ClientError as e:
        raise handle_aws_error(e, f"analyze_aurora_cluster:{cluster_id}")


# ============================================================================
# DYNAMODB FUNCTIONS
# ============================================================================

def list_dynamodb_tables(session, account_id: str, region: str) -> List[DynamoDBTableBasic]:
    """List all DynamoDB tables in a region using paginator"""
    cached = get_cache(account_id, region, "dynamodb", "tables")
    if cached:
        return cached
    
    try:
        dynamodb_client = session.client("dynamodb", region_name=region)
        tables = []
        
        paginator = dynamodb_client.get_paginator("list_tables")
        table_names = []
        for page in paginator.paginate():
            table_names.extend(page.get("TableNames", []))
        
        # Get basic info for each table
        for table_name in table_names:
            try:
                response = dynamodb_client.describe_table(TableName=table_name)
                table = response["Table"]
                
                tables.append(DynamoDBTableBasic(
                    TableName=table["TableName"],
                    TableStatus=table["TableStatus"],
                    CreationDateTime=table["CreationDateTime"].isoformat() if table.get("CreationDateTime") else None,
                    ItemCount=table.get("ItemCount"),
                    TableSizeBytes=table.get("TableSizeBytes")
                ))
            except ClientError:
                continue
        
        set_cache(account_id, region, "dynamodb", "tables", tables)
        return tables
        
    except (ClientError, BotoCoreError) as e:
        raise handle_aws_error(e, "list_dynamodb_tables")


def analyze_dynamodb_table(dynamodb_client, table_name: str) -> DynamoDBTableDetail:
    """Get detailed DynamoDB table information with security analysis"""
    try:
        response = dynamodb_client.describe_table(TableName=table_name)
        table = response["Table"]
        
        # Get tags
        tags = []
        try:
            tags_response = dynamodb_client.list_tags_of_resource(ResourceArn=table["TableArn"])
            tags = [{"Key": tag["Key"], "Value": tag["Value"]} for tag in tags_response.get("Tags", [])]
        except ClientError:
            pass
        
        # Get point-in-time recovery status
        pitr_enabled = False
        try:
            pitr_response = dynamodb_client.describe_continuous_backups(TableName=table_name)
            pitr_status = pitr_response.get("ContinuousBackupsDescription", {}).get("PointInTimeRecoveryDescription", {}).get("PointInTimeRecoveryStatus")
            pitr_enabled = (pitr_status == "ENABLED")
        except ClientError:
            pass
        
        # Build detailed table info
        detail = DynamoDBTableDetail(
            TableName=table["TableName"],
            TableArn=table["TableArn"],
            TableStatus=table["TableStatus"],
            CreationDateTime=table["CreationDateTime"].isoformat(),
            KeySchema=table.get("KeySchema", []),
            AttributeDefinitions=table.get("AttributeDefinitions", []),
            BillingMode=table.get("BillingModeSummary", {}).get("BillingMode", "PROVISIONED"),
            ProvisionedThroughput=table.get("ProvisionedThroughput"),
            ItemCount=table.get("ItemCount", 0),
            TableSizeBytes=table.get("TableSizeBytes", 0),
            SSEDescription=table.get("SSEDescription"),
            StreamSpecification=table.get("StreamSpecification"),
            LatestStreamArn=table.get("LatestStreamArn"),
            PointInTimeRecoveryEnabled=pitr_enabled,
            GlobalSecondaryIndexes=table.get("GlobalSecondaryIndexes", []),
            LocalSecondaryIndexes=table.get("LocalSecondaryIndexes", []),
            Tags=tags,
            recommendations=[],
            security_findings=[]
        )
        
        # Security Analysis
        encryption_enabled = detail.SSEDescription and detail.SSEDescription.get("Status") == "ENABLED"
        if not encryption_enabled:
            detail.security_findings.append({
                "type": "security",
                "severity": "high",
                "message": "Encryption at rest not enabled",
                "recommendation": "Enable encryption at rest using AWS managed or customer managed KMS keys"
            })
        
        if not detail.PointInTimeRecoveryEnabled:
            detail.recommendations.append({
                "type": "backup",
                "severity": "high",
                "message": "Point-in-time recovery (PITR) not enabled",
                "recommendation": "Enable PITR for continuous backups and restore capabilities"
            })
        
        if detail.BillingMode == "PROVISIONED":
            detail.recommendations.append({
                "type": "cost_optimization",
                "severity": "low",
                "message": "Using provisioned billing mode",
                "recommendation": "Consider on-demand mode for unpredictable workloads to optimize costs"
            })
        
        if not detail.StreamSpecification or not detail.StreamSpecification.get("StreamEnabled"):
            detail.recommendations.append({
                "type": "architecture",
                "severity": "low",
                "message": "DynamoDB Streams not enabled",
                "recommendation": "Consider enabling streams for change data capture and event-driven architectures"
            })
        
        # Check for GSI without projection
        for gsi in detail.GlobalSecondaryIndexes:
            projection = gsi.get("Projection", {})
            if projection.get("ProjectionType") == "ALL":
                detail.recommendations.append({
                    "type": "cost_optimization",
                    "severity": "low",
                    "message": f"GSI '{gsi.get('IndexName')}' projects all attributes",
                    "recommendation": "Consider using KEYS_ONLY or INCLUDE projection to reduce storage costs"
                })
        
        return detail
        
    except ClientError as e:
        raise handle_aws_error(e, f"analyze_dynamodb_table:{table_name}")


# ============================================================================
# ELASTICACHE FUNCTIONS
# ============================================================================

def list_elasticache_clusters(session, account_id: str, region: str) -> List[ElastiCacheClusterBasic]:
    """List all ElastiCache clusters in a region using paginator"""
    cached = get_cache(account_id, region, "elasticache", "clusters")
    if cached:
        return cached
    
    try:
        elasticache_client = session.client("elasticache", region_name=region)
        clusters = []
        
        paginator = elasticache_client.get_paginator("describe_cache_clusters")
        for page in paginator.paginate():
            for cluster in page.get("CacheClusters", []):
                clusters.append(ElastiCacheClusterBasic(
                    CacheClusterId=cluster["CacheClusterId"],
                    CacheNodeType=cluster["CacheNodeType"],
                    Engine=cluster["Engine"],
                    CacheClusterStatus=cluster["CacheClusterStatus"],
                    NumCacheNodes=cluster.get("NumCacheNodes", 0)
                ))
        
        set_cache(account_id, region, "elasticache", "clusters", clusters)
        return clusters
        
    except (ClientError, BotoCoreError) as e:
        raise handle_aws_error(e, "list_elasticache_clusters")


def analyze_elasticache_cluster(elasticache_client, cluster_id: str) -> ElastiCacheClusterDetail:
    """Get detailed ElastiCache cluster information with security analysis"""
    try:
        response = elasticache_client.describe_cache_clusters(
            CacheClusterId=cluster_id,
            ShowCacheNodeInfo=True
        )
        
        if not response["CacheClusters"]:
            raise HTTPException(status_code=404, detail=f"ElastiCache cluster {cluster_id} not found")
        
        cluster = response["CacheClusters"][0]
        
        # Get tags
        tags = []
        cluster_arn = cluster.get("ARN")
        if cluster_arn:
            try:
                tags_response = elasticache_client.list_tags_for_resource(ResourceName=cluster_arn)
                tags = [{"Key": tag["Key"], "Value": tag["Value"]} for tag in tags_response.get("TagList", [])]
            except ClientError:
                pass
        
        # Build detailed cluster info
        detail = ElastiCacheClusterDetail(
            CacheClusterId=cluster["CacheClusterId"],
            CacheClusterArn=cluster.get("ARN"),
            Engine=cluster["Engine"],
            EngineVersion=cluster["EngineVersion"],
            CacheClusterStatus=cluster["CacheClusterStatus"],
            CacheNodeType=cluster["CacheNodeType"],
            NumCacheNodes=cluster.get("NumCacheNodes", 0),
            PreferredAvailabilityZone=cluster.get("PreferredAvailabilityZone"),
            CacheClusterCreateTime=cluster.get("CacheClusterCreateTime").isoformat() if cluster.get("CacheClusterCreateTime") else None,
            PreferredMaintenanceWindow=cluster.get("PreferredMaintenanceWindow"),
            CacheSubnetGroupName=cluster.get("CacheSubnetGroupName"),
            SecurityGroups=[
                {"SecurityGroupId": sg["SecurityGroupId"], "Status": sg["Status"]}
                for sg in cluster.get("SecurityGroups", [])
            ],
            AtRestEncryptionEnabled=cluster.get("AtRestEncryptionEnabled", False),
            TransitEncryptionEnabled=cluster.get("TransitEncryptionEnabled", False),
            AuthTokenEnabled=cluster.get("AuthTokenEnabled", False),
            SnapshotRetentionLimit=cluster.get("SnapshotRetentionLimit", 0),
            SnapshotWindow=cluster.get("SnapshotWindow"),
            AutoMinorVersionUpgrade=cluster.get("AutoMinorVersionUpgrade", True),
            Tags=tags,
            recommendations=[],
            security_findings=[]
        )
        
        # Security Analysis
        if not detail.AtRestEncryptionEnabled:
            detail.security_findings.append({
                "type": "security",
                "severity": "high",
                "message": "Encryption at rest not enabled",
                "recommendation": "Enable encryption at rest for data protection"
            })
        
        if not detail.TransitEncryptionEnabled:
            detail.security_findings.append({
                "type": "security",
                "severity": "high",
                "message": "Encryption in transit not enabled",
                "recommendation": "Enable TLS encryption for data in transit"
            })
        
        if cluster["Engine"] == "redis" and not detail.AuthTokenEnabled:
            detail.security_findings.append({
                "type": "security",
                "severity": "critical",
                "message": "Redis AUTH token not enabled",
                "recommendation": "Enable AUTH token for Redis authentication"
            })
        
        if detail.SnapshotRetentionLimit == 0:
            detail.recommendations.append({
                "type": "backup",
                "severity": "medium",
                "message": "Automatic backups disabled",
                "recommendation": "Enable automatic backups with appropriate retention period"
            })
        
        if detail.NumCacheNodes < 2:
            detail.recommendations.append({
                "type": "availability",
                "severity": "medium",
                "message": "Cluster has only one cache node",
                "recommendation": "Use multiple nodes or replication groups for high availability"
            })
        
        if not detail.AutoMinorVersionUpgrade:
            detail.recommendations.append({
                "type": "maintenance",
                "severity": "low",
                "message": "Automatic minor version upgrade disabled",
                "recommendation": "Enable auto minor version upgrades for security patches"
            })
        
        return detail
        
    except ClientError as e:
        raise handle_aws_error(e, f"analyze_elasticache_cluster:{cluster_id}")


# ============================================================================
# API ROUTES
# ============================================================================

@router.get(
    "/database/{service}",
    response_model=StandardResponse,
    summary="List all resources for a database service",
    description="Returns a list of all resources (RDS instances, Aurora clusters, DynamoDB tables, or ElastiCache clusters) in the specified region",
    responses={
        200: {
            "description": "Successful response",
            "content": {
                "application/json": {
                    "examples": {
                        "rds": {
                            "summary": "RDS Instances Example",
                            "value": {
                                "status": "success",
                                "message": "Retrieved 5 RDS instances",
                                "data": [
                                    {
                                        "DBInstanceIdentifier": "production-db",
                                        "DBInstanceClass": "db.t3.medium",
                                        "Engine": "postgres",
                                        "DBInstanceStatus": "available",
                                        "AvailabilityZone": "us-east-1a",
                                        "MultiAZ": True
                                    }
                                ],
                                "metadata": {
                                    "total_count": 5,
                                    "service": "rds",
                                    "account_id": "123456789012",
                                    "region": "us-east-1"
                                }
                            }
                        },
                        "aurora": {
                            "summary": "Aurora Clusters Example",
                            "value": {
                                "status": "success",
                                "message": "Retrieved 3 Aurora clusters",
                                "data": [
                                    {
                                        "DBClusterIdentifier": "prod-aurora-cluster",
                                        "Engine": "aurora-mysql",
                                        "Status": "available",
                                        "MultiAZ": True,
                                        "ClusterMembers": 3
                                    }
                                ],
                                "metadata": {
                                    "total_count": 3,
                                    "service": "aurora",
                                    "account_id": "123456789012",
                                    "region": "us-east-1"
                                }
                            }
                        },
                        "dynamodb": {
                            "summary": "DynamoDB Tables Example",
                            "value": {
                                "status": "success",
                                "message": "Retrieved 10 DynamoDB tables",
                                "data": [
                                    {
                                        "TableName": "Users",
                                        "TableStatus": "ACTIVE",
                                        "CreationDateTime": "2024-01-15T10:30:00Z",
                                        "ItemCount": 1000000,
                                        "TableSizeBytes": 5242880
                                    }
                                ],
                                "metadata": {
                                    "total_count": 10,
                                    "service": "dynamodb",
                                    "account_id": "123456789012",
                                    "region": "us-east-1"
                                }
                            }
                        },
                        "elasticache": {
                            "summary": "ElastiCache Clusters Example",
                            "value": {
                                "status": "success",
                                "message": "Retrieved 2 ElastiCache clusters",
                                "data": [
                                    {
                                        "CacheClusterId": "redis-prod-001",
                                        "CacheNodeType": "cache.t3.medium",
                                        "Engine": "redis",
                                        "CacheClusterStatus": "available",
                                        "NumCacheNodes": 3
                                    }
                                ],
                                "metadata": {
                                    "total_count": 2,
                                    "service": "elasticache",
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
async def list_database_resources(
    request: Request,
    service: str,
    account_id: str = Query(..., description="AWS Account ID", example="123456789012"),
    region: str = Query("us-east-1", description="AWS Region", example="us-east-1")
):
    """List all resources for a specific database service (rds, aurora, dynamodb, or elasticache)"""
    
    if service not in DATABASE_SERVICES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid service '{service}'. Supported services: {', '.join(DATABASE_SERVICES)}"
        )
    
    session = getattr(request.state, "session", None)
    if not session:
        raise HTTPException(status_code=401, detail="AWS session not found")
    
    try:
        if service == "rds":
            resources = list_rds_instances(session, account_id, region)
            data = [instance.dict() for instance in resources]
        elif service == "aurora":
            resources = list_aurora_clusters(session, account_id, region)
            data = [cluster.dict() for cluster in resources]
        elif service == "dynamodb":
            resources = list_dynamodb_tables(session, account_id, region)
            data = [table.dict() for table in resources]
        elif service == "elasticache":
            resources = list_elasticache_clusters(session, account_id, region)
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
        logger.exception(f"Unexpected error in list_database_resources for {service}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post(
    "/database/{service}",
    response_model=StandardResponse,
    summary="Get detailed resource information for a database service",
    description="Returns detailed information and security analysis for specified resources (RDS instances, Aurora clusters, DynamoDB tables, or ElastiCache clusters)",
    responses={
        200: {
            "description": "Successful response",
            "content": {
                "application/json": {
                    "examples": {
                        "rds": {
                            "summary": "RDS Instance Details Example",
                            "value": {
                                "status": "success",
                                "message": "Retrieved details for 1 rds resources",
                                "data": [
                                    {
                                        "DBInstanceIdentifier": "production-db",
                                        "Engine": "postgres",
                                        "StorageEncrypted": False,
                                        "PubliclyAccessible": True,
                                        "MultiAZ": False,
                                        "BackupRetentionPeriod": 0,
                                        "security_findings": [
                                            {
                                                "type": "security",
                                                "severity": "high",
                                                "message": "Storage encryption not enabled"
                                            },
                                            {
                                                "type": "security",
                                                "severity": "critical",
                                                "message": "Database is publicly accessible"
                                            },
                                            {
                                                "type": "backup",
                                                "severity": "high",
                                                "message": "Automated backups disabled"
                                            }
                                        ],
                                        "recommendations": [
                                            {
                                                "type": "availability",
                                                "severity": "high",
                                                "message": "Multi-AZ deployment not enabled"
                                            }
                                        ]
                                    }
                                ]
                            }
                        },
                        "dynamodb": {
                            "summary": "DynamoDB Table Details Example",
                            "value": {
                                "status": "success",
                                "message": "Retrieved details for 1 dynamodb resources",
                                "data": [
                                    {
                                        "TableName": "Users",
                                        "BillingMode": "PAY_PER_REQUEST",
                                        "PointInTimeRecoveryEnabled": False,
                                        "SSEDescription": None,
                                        "security_findings": [
                                            {
                                                "type": "security",
                                                "severity": "high",
                                                "message": "Encryption at rest not enabled"
                                            }
                                        ],
                                        "recommendations": [
                                            {
                                                "type": "backup",
                                                "severity": "high",
                                                "message": "Point-in-time recovery not enabled"
                                            }
                                        ]
                                    }
                                ]
                            }
                        }
                    }
                }
            }
        }
    }
)
async def get_database_details(
    request: Request,
    service: str,
    payload: ResourceIdsRequest = Body(...),
    account_id: str = Query(..., description="AWS Account ID"),
    region: str = Query("us-east-1", description="AWS Region")
):
    """Get detailed information for multiple resources of a specific database service"""
    
    if service not in DATABASE_SERVICES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid service '{service}'. Supported services: {', '.join(DATABASE_SERVICES)}"
        )
    
    session = getattr(request.state, "session", None)
    if not session:
        raise HTTPException(status_code=401, detail="AWS session not found")
    
    try:
        details = []
        errors = []
        
        if service == "rds":
            rds_client = session.client("rds", region_name=region)
            for instance_id in payload.resource_ids:
                try:
                    detail = analyze_rds_instance(rds_client, instance_id)
                    details.append(detail.dict())
                except HTTPException as he:
                    errors.append(f"{instance_id}: {he.detail}")
                except Exception as e:
                    errors.append(f"{instance_id}: {str(e)}")
        
        elif service == "aurora":
            rds_client = session.client("rds", region_name=region)
            for cluster_id in payload.resource_ids:
                try:
                    detail = analyze_aurora_cluster(rds_client, cluster_id)
                    details.append(detail.dict())
                except HTTPException as he:
                    errors.append(f"{cluster_id}: {he.detail}")
                except Exception as e:
                    errors.append(f"{cluster_id}: {str(e)}")
        
        elif service == "dynamodb":
            dynamodb_client = session.client("dynamodb", region_name=region)
            for table_name in payload.resource_ids:
                try:
                    detail = analyze_dynamodb_table(dynamodb_client, table_name)
                    details.append(detail.dict())
                except HTTPException as he:
                    errors.append(f"{table_name}: {he.detail}")
                except Exception as e:
                    errors.append(f"{table_name}: {str(e)}")
        
        elif service == "elasticache":
            elasticache_client = session.client("elasticache", region_name=region)
            for cluster_id in payload.resource_ids:
                try:
                    detail = analyze_elasticache_cluster(elasticache_client, cluster_id)
                    details.append(detail.dict())
                except HTTPException as he:
                    errors.append(f"{cluster_id}: {he.detail}")
                except Exception as e:
                    errors.append(f"{cluster_id}: {str(e)}")
        
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
        logger.exception(f"Unexpected error in get_database_details for {service}")
        raise HTTPException(status_code=500, detail=str(e))