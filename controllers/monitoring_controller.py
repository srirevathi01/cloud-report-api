"""
AWS Monitoring & Logs Services Controller
Handles CloudWatch, CloudTrail, and X-Ray resources with comprehensive security and performance recommendations
"""

from fastapi import APIRouter, Request, HTTPException, Query, Body
from pydantic import BaseModel, Field, validator
from botocore.exceptions import ClientError, BotoCoreError
from typing import Dict, Any, List, Optional
from datetime import datetime
import logging
import time
import boto3  # boto3 used to create sessions

router = APIRouter()
logger = logging.getLogger(__name__)

# ============================================================================
# CONSTANTS
# ============================================================================
MONITORING_SERVICES = ["cloudwatch", "cloudtrail", "xray"]
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
        description="List of resource names/IDs to fetch details for",
        example=["log-group-1", "trail-name-1"]
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


# ============================================================================
# CLOUDWATCH MODELS
# ============================================================================

class CloudWatchLogGroupBasic(BaseModel):
    """Basic CloudWatch Log Group information"""
    logGroupName: str
    creationTime: Optional[int] = None
    retentionInDays: Optional[int] = None
    storedBytes: Optional[int] = None
    metricFilterCount: int = 0


class CloudWatchLogGroupDetail(BaseModel):
    """Detailed CloudWatch Log Group information with security analysis"""
    logGroupName: str
    creationTime: Optional[str] = None
    retentionInDays: Optional[int] = None
    storedBytes: int = 0
    arn: str
    metricFilterCount: int = 0
    subscriptionFilters: List[Dict[str, Any]] = []
    kmsKeyId: Optional[str] = None
    tags: Dict[str, str] = {}
    recommendations: List[Dict[str, Any]] = []
    security_findings: List[Dict[str, Any]] = []


class CloudWatchAlarmBasic(BaseModel):
    """Basic CloudWatch Alarm information"""
    AlarmName: str
    StateValue: str
    StateReason: Optional[str] = None
    MetricName: Optional[str] = None
    Namespace: Optional[str] = None


class CloudWatchAlarmDetail(BaseModel):
    """Detailed CloudWatch Alarm information"""
    AlarmName: str
    AlarmArn: str
    StateValue: str
    StateReason: Optional[str] = None
    StateUpdatedTimestamp: Optional[str] = None
    MetricName: Optional[str] = None
    Namespace: Optional[str] = None
    Statistic: Optional[str] = None
    Dimensions: List[Dict[str, str]] = []
    Period: int = 0
    EvaluationPeriods: int = 0
    Threshold: Optional[float] = None
    ComparisonOperator: Optional[str] = None
    AlarmActions: List[str] = []
    OKActions: List[str] = []
    InsufficientDataActions: List[str] = []
    Tags: List[Dict[str, str]] = []
    recommendations: List[Dict[str, Any]] = []


# ============================================================================
# CLOUDTRAIL MODELS
# ============================================================================

class CloudTrailTrailBasic(BaseModel):
    """Basic CloudTrail Trail information"""
    Name: str
    S3BucketName: str
    IsMultiRegionTrail: bool
    HomeRegion: str
    HasCustomEventSelectors: bool


class CloudTrailTrailDetail(BaseModel):
    """Detailed CloudTrail Trail information with security analysis"""
    Name: str
    TrailArn: str
    S3BucketName: str
    IsMultiRegionTrail: bool
    HomeRegion: str
    IncludeGlobalServiceEvents: bool
    IsOrganizationTrail: bool
    HasCustomEventSelectors: bool
    LogFileValidationEnabled: bool
    CloudWatchLogsGroupArn: Optional[str] = None
    CloudWatchLogsRoleArn: Optional[str] = None
    KMSKeyId: Optional[str] = None
    SNSTopicName: Optional[str] = None
    HasInsightSelectors: bool = False
    IsLogging: bool = False
    LatestDeliveryTime: Optional[str] = None
    LatestDigestDeliveryTime: Optional[str] = None
    Tags: List[Dict[str, str]] = []
    recommendations: List[Dict[str, Any]] = []
    security_findings: List[Dict[str, Any]] = []


# ============================================================================
# X-RAY MODELS
# ============================================================================

class XRayGroupBasic(BaseModel):
    """Basic X-Ray Group information"""
    GroupName: str
    GroupArn: str
    InsightsConfiguration: Dict[str, bool] = {}


class XRayGroupDetail(BaseModel):
    """Detailed X-Ray Group information with security analysis"""
    GroupName: str
    GroupArn: str
    FilterExpression: str
    InsightsConfiguration: Dict[str, bool] = {}
    CreationTime: Optional[str] = None
    Tags: Dict[str, str] = {}
    recommendations: List[Dict[str, Any]] = []
    security_findings: List[Dict[str, Any]] = []


class XRayTraceSummaryBasic(BaseModel):
    """Basic X-Ray Trace Summary information"""
    Id: str
    StartTime: str
    Duration: float
    ResponseStatus: int
    HasError: bool
    HasFault: bool
    HasThrottle: bool


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
        elif error_code in ["ResourceNotFoundException", "InvalidLogGroupName", "TrailNotFoundException"]:
            status_code = 404
        
        return HTTPException(status_code=status_code, detail=f"{error_code}: {error_msg}")
    else:
        logger.error(f"Unexpected error in {context}: {str(e)}")
        return HTTPException(status_code=500, detail=str(e))


# ============================================================================
# CLOUDWATCH FUNCTIONS
# ============================================================================

def list_cloudwatch_log_groups(session, account_id: str, region: str) -> List[CloudWatchLogGroupBasic]:
    """List all CloudWatch Log Groups in a region using paginator"""
    cached = get_cache(account_id, region, "cloudwatch", "log_groups")
    if cached:
        return cached
    
    try:
        logs_client = session.client("logs", region_name=region)
        log_groups = []
        
        paginator = logs_client.get_paginator("describe_log_groups")
        for page in paginator.paginate():
            for lg in page.get("logGroups", []):
                log_groups.append(CloudWatchLogGroupBasic(
                    logGroupName=lg["logGroupName"],
                    creationTime=lg.get("creationTime"),
                    retentionInDays=lg.get("retentionInDays"),
                    storedBytes=lg.get("storedBytes", 0),
                    metricFilterCount=lg.get("metricFilterCount", 0)
                ))
        
        set_cache(account_id, region, "cloudwatch", "log_groups", log_groups)
        return log_groups
        
    except (ClientError, BotoCoreError) as e:
        raise handle_aws_error(e, "list_cloudwatch_log_groups")


def analyze_cloudwatch_log_group(logs_client, log_group_name: str, account_id: str) -> CloudWatchLogGroupDetail:
    """Get detailed CloudWatch Log Group information with security analysis"""
    try:
        response = logs_client.describe_log_groups(logGroupNamePrefix=log_group_name)
        
        log_groups = [lg for lg in response.get("logGroups", []) if lg["logGroupName"] == log_group_name]
        if not log_groups:
            raise HTTPException(status_code=404, detail=f"Log group {log_group_name} not found")
        
        lg = log_groups[0]
        
        # Get subscription filters
        sub_filters = []
        try:
            sub_response = logs_client.describe_subscription_filters(logGroupName=log_group_name)
            sub_filters = sub_response.get("subscriptionFilters", [])
        except ClientError:
            pass
        
        # Get tags
        tags = {}
        try:
            tags_response = logs_client.list_tags_log_group(logGroupName=log_group_name)
            tags = tags_response.get("tags", {})
        except ClientError:
            pass
        
        detail = CloudWatchLogGroupDetail(
            logGroupName=lg["logGroupName"],
            creationTime=datetime.fromtimestamp(lg.get("creationTime", 0) / 1000).isoformat() if lg.get("creationTime") else None,
            retentionInDays=lg.get("retentionInDays"),
            storedBytes=lg.get("storedBytes", 0),
            arn=lg.get("arn", ""),
            metricFilterCount=lg.get("metricFilterCount", 0),
            subscriptionFilters=sub_filters,
            kmsKeyId=lg.get("kmsKeyId"),
            tags=tags,
            recommendations=[],
            security_findings=[]
        )
        
        # Security Analysis
        if not lg.get("kmsKeyId"):
            detail.security_findings.append({
                "type": "security",
                "severity": "high",
                "message": "Log group not encrypted with KMS",
                "recommendation": "Enable KMS encryption for log group to protect sensitive data at rest"
            })
        
        if not lg.get("retentionInDays"):
            detail.recommendations.append({
                "type": "retention",
                "severity": "medium",
                "message": "Log retention not configured (logs retained indefinitely)",
                "recommendation": "Set appropriate retention period based on compliance requirements"
            })
        
        if detail.storedBytes > 1099511627776:  # > 1TB
            detail.recommendations.append({
                "type": "cost_optimization",
                "severity": "low",
                "message": "Large log group storage (>1TB)",
                "recommendation": "Review log retention policies and consider archiving old logs to S3"
            })
        
        if not sub_filters:
            detail.recommendations.append({
                "type": "monitoring",
                "severity": "low",
                "message": "No subscription filters configured",
                "recommendation": "Consider setting up subscription filters for real-time log analysis"
            })
        
        if not tags:
            detail.recommendations.append({
                "type": "governance",
                "severity": "low",
                "message": "No tags applied to log group",
                "recommendation": "Add tags for cost allocation and resource organization"
            })
        
        return detail
        
    except ClientError as e:
        raise handle_aws_error(e, f"analyze_cloudwatch_log_group:{log_group_name}")


def list_cloudwatch_alarms(session, account_id: str, region: str) -> List[CloudWatchAlarmBasic]:
    """List all CloudWatch Alarms in a region using paginator"""
    cached = get_cache(account_id, region, "cloudwatch", "alarms")
    if cached:
        return cached
    
    try:
        cw_client = session.client("cloudwatch", region_name=region)
        alarms = []
        
        paginator = cw_client.get_paginator("describe_alarms")
        for page in paginator.paginate():
            for alarm in page.get("MetricAlarms", []):
                alarms.append(CloudWatchAlarmBasic(
                    AlarmName=alarm["AlarmName"],
                    StateValue=alarm["StateValue"],
                    StateReason=alarm.get("StateReason"),
                    MetricName=alarm.get("MetricName"),
                    Namespace=alarm.get("Namespace")
                ))
        
        set_cache(account_id, region, "cloudwatch", "alarms", alarms)
        return alarms
        
    except (ClientError, BotoCoreError) as e:
        raise handle_aws_error(e, "list_cloudwatch_alarms")


def analyze_cloudwatch_alarm(cw_client, alarm_name: str) -> CloudWatchAlarmDetail:
    """Get detailed CloudWatch Alarm information"""
    try:
        response = cw_client.describe_alarms(AlarmNames=[alarm_name])
        
        if not response.get("MetricAlarms"):
            raise HTTPException(status_code=404, detail=f"Alarm {alarm_name} not found")
        
        alarm = response["MetricAlarms"][0]
        
        # Get tags
        tags = []
        try:
            tags_response = cw_client.list_tags_for_resource(ResourceARN=alarm["AlarmArn"])
            tags = [{"Key": tag["Key"], "Value": tag["Value"]} for tag in tags_response.get("Tags", [])]
        except ClientError:
            pass
        
        detail = CloudWatchAlarmDetail(
            AlarmName=alarm["AlarmName"],
            AlarmArn=alarm["AlarmArn"],
            StateValue=alarm["StateValue"],
            StateReason=alarm.get("StateReason"),
            StateUpdatedTimestamp=alarm.get("StateUpdatedTimestamp").isoformat() if alarm.get("StateUpdatedTimestamp") else None,
            MetricName=alarm.get("MetricName"),
            Namespace=alarm.get("Namespace"),
            Statistic=alarm.get("Statistic"),
            Dimensions=[{"Name": d["Name"], "Value": d["Value"]} for d in alarm.get("Dimensions", [])],
            Period=alarm.get("Period", 0),
            EvaluationPeriods=alarm.get("EvaluationPeriods", 0),
            Threshold=alarm.get("Threshold"),
            ComparisonOperator=alarm.get("ComparisonOperator"),
            AlarmActions=alarm.get("AlarmActions", []),
            OKActions=alarm.get("OKActions", []),
            InsufficientDataActions=alarm.get("InsufficientDataActions", []),
            Tags=tags,
            recommendations=[]
        )
        
        # Recommendations
        if not detail.AlarmActions:
            detail.recommendations.append({
                "type": "monitoring",
                "severity": "medium",
                "message": "No alarm actions configured",
                "recommendation": "Add SNS notifications or auto-scaling actions for alarm state changes"
            })
        
        if detail.EvaluationPeriods < 2:
            detail.recommendations.append({
                "type": "monitoring",
                "severity": "low",
                "message": "Low evaluation period (quick to trigger)",
                "recommendation": "Consider increasing evaluation periods to reduce false positives"
            })
        
        return detail
        
    except ClientError as e:
        raise handle_aws_error(e, f"analyze_cloudwatch_alarm:{alarm_name}")


# ============================================================================
# CLOUDTRAIL FUNCTIONS
# ============================================================================

def list_cloudtrail_trails(session, account_id: str, region: str) -> List[CloudTrailTrailBasic]:
    """List all CloudTrail Trails in a region using paginator"""
    cached = get_cache(account_id, region, "cloudtrail", "trails")
    if cached:
        return cached
    
    try:
        ct_client = session.client("cloudtrail", region_name=region)
        trails = []
        
        paginator = ct_client.get_paginator("describe_trails")
        # describe_trails uses includeShadowTrails in call; some boto3 variants accept it on client
        for page in paginator.paginate():
            for trail in page.get("trailList", []):
                trails.append(CloudTrailTrailBasic(
                    Name=trail["Name"],
                    S3BucketName=trail.get("S3BucketName", ""),
                    IsMultiRegionTrail=trail.get("IsMultiRegionTrail", False),
                    HomeRegion=trail.get("HomeRegion", region),
                    HasCustomEventSelectors=trail.get("HasCustomEventSelectors", False)
                ))
        
        set_cache(account_id, region, "cloudtrail", "trails", trails)
        return trails
        
    except (ClientError, BotoCoreError) as e:
        raise handle_aws_error(e, "list_cloudtrail_trails")


def analyze_cloudtrail_trail(ct_client, trail_name: str) -> CloudTrailTrailDetail:
    """Get detailed CloudTrail Trail information with security analysis"""
    try:
        response = ct_client.describe_trails(trailNameList=[trail_name], includeShadowTrails=True)
        
        if not response.get("trailList"):
            raise HTTPException(status_code=404, detail=f"Trail {trail_name} not found")
        
        trail = response["trailList"][0]
        
        # Get trail status
        status_response = {}
        try:
            status_response = ct_client.get_trail_status(Name=trail_name)
        except ClientError:
            status_response = {}
        
        # Get tags
        tags = []
        try:
            tags_response = ct_client.list_tags(ResourceIdList=[trail.get("TrailARN", "")])
            for tag_list in tags_response.get("ResourceTagList", []):
                tags = [{"Key": tag["Key"], "Value": tag["Value"]} for tag in tag_list.get("TagsList", [])]
        except ClientError:
            pass
        
        detail = CloudTrailTrailDetail(
            Name=trail["Name"],
            TrailArn=trail.get("TrailARN", ""),
            S3BucketName=trail.get("S3BucketName", ""),
            IsMultiRegionTrail=trail.get("IsMultiRegionTrail", False),
            HomeRegion=trail.get("HomeRegion", ""),
            IncludeGlobalServiceEvents=trail.get("IncludeGlobalServiceEvents", False),
            IsOrganizationTrail=trail.get("IsOrganizationTrail", False),
            HasCustomEventSelectors=trail.get("HasCustomEventSelectors", False),
            CloudWatchLogsGroupArn=trail.get("CloudWatchLogsGroupArn"),
            CloudWatchLogsRoleArn=trail.get("CloudWatchLogsRoleArn"),
            KMSKeyId=trail.get("KMSKeyId"),
            SNSTopicName=trail.get("SNSTopicName"),
            HasInsightSelectors=trail.get("HasInsightSelectors", False),
            IsLogging=status_response.get("IsLogging", False),
            LatestDeliveryTime=status_response.get("LatestDeliveryTime").isoformat() if status_response.get("LatestDeliveryTime") else None,
            LatestDigestDeliveryTime=status_response.get("LatestDigestDeliveryTime").isoformat() if status_response.get("LatestDigestDeliveryTime") else None,
            Tags=tags,
            recommendations=[],
            security_findings=[]
        )
        
        # Security Analysis
        if not detail.IsLogging:
            detail.security_findings.append({
                "type": "security",
                "severity": "critical",
                "message": "CloudTrail logging is disabled",
                "recommendation": "Enable CloudTrail logging to maintain audit trail of API calls"
            })
        
        if not detail.KMSKeyId:
            detail.security_findings.append({
                "type": "security",
                "severity": "high",
                "message": "S3 SSE-KMS encryption not enabled",
                "recommendation": "Enable KMS encryption for log files to protect sensitive data"
            })
        
        if not detail.IsMultiRegionTrail:
            detail.recommendations.append({
                "type": "security",
                "severity": "high",
                "message": "Multi-region trail not enabled",
                "recommendation": "Enable multi-region trail to capture API calls across all regions"
            })
        
        if not detail.CloudWatchLogsGroupArn:
            detail.recommendations.append({
                "type": "monitoring",
                "severity": "medium",
                "message": "CloudWatch Logs delivery not configured",
                "recommendation": "Enable CloudWatch Logs integration for real-time monitoring and alerting"
            })
        
        if not detail.HasInsightSelectors:
            detail.recommendations.append({
                "type": "security",
                "severity": "low",
                "message": "CloudTrail Insights not enabled",
                "recommendation": "Enable Insights to automatically detect unusual API activity"
            })
        
        if not detail.HasCustomEventSelectors and detail.IsMultiRegionTrail:
            detail.recommendations.append({
                "type": "optimization",
                "severity": "low",
                "message": "Custom event selectors not configured",
                "recommendation": "Use custom event selectors to log only relevant events and reduce costs"
            })
        
        return detail
        
    except ClientError as e:
        raise handle_aws_error(e, f"analyze_cloudtrail_trail:{trail_name}")


# ============================================================================
# X-RAY FUNCTIONS
# ============================================================================

def list_xray_groups(session, account_id: str, region: str) -> List[XRayGroupBasic]:
    """List all X-Ray Groups in a region using paginator"""
    cached = get_cache(account_id, region, "xray", "groups")
    if cached:
        return cached
    
    try:
        xray_client = session.client("xray", region_name=region)
        groups = []
        
        paginator = xray_client.get_paginator("get_groups")
        for page in paginator.paginate():
            for group in page.get("Groups", []):
                groups.append(XRayGroupBasic(
                    GroupName=group["GroupName"],
                    GroupArn=group["GroupArn"],
                    InsightsConfiguration=group.get("InsightsConfiguration", {})
                ))
        
        set_cache(account_id, region, "xray", "groups", groups)
        return groups
        
    except (ClientError, BotoCoreError) as e:
        raise handle_aws_error(e, "list_xray_groups")


def analyze_xray_group(xray_client, group_name: str) -> XRayGroupDetail:
    """Get detailed X-Ray Group information with security analysis"""
    try:
        response = xray_client.get_group(GroupName=group_name)
        group = response.get("Group")
        
        if not group:
            raise HTTPException(status_code=404, detail=f"X-Ray group {group_name} not found")
        
        # Get tags
        tags = {}
        try:
            tags_response = xray_client.list_tags_for_resource(ResourceARN=group["GroupArn"])
            tags = tags_response.get("Tags", {})
        except ClientError:
            pass
        
        detail = XRayGroupDetail(
            GroupName=group["GroupName"],
            GroupArn=group["GroupArn"],
            FilterExpression=group.get("FilterExpression", ""),
            InsightsConfiguration=group.get("InsightsConfiguration", {}),
            CreationTime=group.get("CreationTime").isoformat() if group.get("CreationTime") else None,
            Tags=tags,
            recommendations=[],
            security_findings=[]
        )
        
        # Recommendations
        insights_config = detail.InsightsConfiguration or {}
        if not insights_config.get("InsightsEnabled"):
            detail.recommendations.append({
                "type": "monitoring",
                "severity": "medium",
                "message": "X-Ray Insights not enabled",
                "recommendation": "Enable Insights to automatically detect anomalies in performance"
            })
        
        if not detail.FilterExpression:
            detail.recommendations.append({
                "type": "optimization",
                "severity": "low",
                "message": "No filter expression configured",
                "recommendation": "Use filter expressions to focus on specific traces and reduce costs"
            })
        
        if not tags:
            detail.recommendations.append({
                "type": "governance",
                "severity": "low",
                "message": "No tags applied to group",
                "recommendation": "Add tags for cost allocation and resource organization"
            })
        
        return detail
        
    except ClientError as e:
        raise handle_aws_error(e, f"analyze_xray_group:{group_name}")


def list_xray_traces(session, account_id: str, region: str) -> List[XRayTraceSummaryBasic]:
    """List recent X-Ray Traces in a region"""
    cached = get_cache(account_id, region, "xray", "traces")
    if cached:
        return cached
    
    try:
        xray_client = session.client("xray", region_name=region)
        traces = []
        
        # Use time window for trace summaries (last 1 hour). This is safer than no time range.
        end_time = int(time.time())
        start_time = end_time - 3600  # last hour
        response = xray_client.get_trace_summaries(StartTime=datetime.fromtimestamp(start_time), EndTime=datetime.fromtimestamp(end_time))
        
        for trace in response.get("TraceSummaries", [])[:50]:  # Limit to 50
            traces.append(XRayTraceSummaryBasic(
                Id=trace["Id"],
                StartTime=datetime.fromtimestamp(trace.get("StartTime", 0)).isoformat() if trace.get("StartTime") else "",
                Duration=trace.get("Duration", 0),
                ResponseStatus=trace.get("Http", {}).get("Status", 0),
                HasError=trace.get("HasError", False),
                HasFault=trace.get("HasFault", False),
                HasThrottle=trace.get("HasThrottle", False)
            ))
        
        set_cache(account_id, region, "xray", "traces", traces)
        return traces
        
    except (ClientError, BotoCoreError) as e:
        raise handle_aws_error(e, "list_xray_traces")


# ============================================================================
# HELPERS
# ============================================================================

def get_boto3_session_for_account(account_id: str = None) -> boto3.Session:
    """
    Create a boto3 Session.
    NOTE: If cross-account role assumption is required, implement STS assume-role flow here using account_id.
    For now, return the default session. Caller may supply credentials via environment or IAM role.
    """
    # TODO: implement assume-role if account_id != current
    return boto3.Session()


# ============================================================================
# API ROUTES
# ============================================================================

@router.get(
    "/monitoring/{service}",
    response_model=StandardResponse,
    summary="List all resources for a monitoring service",
    description="Returns a list of all resources (Log Groups, Alarms, Trails, Groups, etc.) in the specified region",
    responses={
        200: {
            "description": "Successful response",
            "content": {
                "application/json": {
                    "examples": {
                        "cloudwatch_logs": {
                            "summary": "CloudWatch Log Groups Example",
                            "value": {
                                "status": "success",
                                "message": "Retrieved 8 cloudwatch resources",
                                "data": [
                                    {
                                        "logGroupName": "/aws/lambda/my-function",
                                        "creationTime": 1625097600000,
                                        "retentionInDays": 30,
                                        "storedBytes": 1073741824,
                                        "metricFilterCount": 2
                                    },
                                    {
                                        "logGroupName": "/aws/ecs/my-service",
                                        "creationTime": 1625097600000,
                                        "retentionInDays": None,
                                        "storedBytes": 2147483648,
                                        "metricFilterCount": 0
                                    }
                                ],
                                "metadata": {
                                    "total_count": 8,
                                    "service": "cloudwatch",
                                    "account_id": "123456789012",
                                    "region": "us-east-1"
                                }
                            }
                        },
                        "cloudtrail": {
                            "summary": "CloudTrail Trails Example",
                            "value": {
                                "status": "success",
                                "message": "Retrieved 2 cloudtrail resources",
                                "data": [
                                    {
                                        "Name": "organization-trail",
                                        "S3BucketName": "my-cloudtrail-bucket",
                                        "IsMultiRegionTrail": True,
                                        "HomeRegion": "us-east-1",
                                        "HasCustomEventSelectors": True
                                    }
                                ],
                                "metadata": {
                                    "total_count": 2,
                                    "service": "cloudtrail",
                                    "account_id": "123456789012",
                                    "region": "us-east-1"
                                }
                            }
                        },
                        "xray": {
                            "summary": "X-Ray Groups Example",
                            "value": {
                                "status": "success",
                                "message": "Retrieved 3 xray resources",
                                "data": [
                                    {
                                        "GroupName": "production-apps",
                                        "GroupArn": "arn:aws:xray:us-east-1:123456789012:group/production-apps",
                                        "InsightsConfiguration": {
                                            "InsightsEnabled": True,
                                            "NotificationsEnabled": True
                                        }
                                    }
                                ],
                                "metadata": {
                                    "total_count": 3,
                                    "service": "xray",
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
async def list_monitoring_resources(
    service: str,
    account_id: str = Query(..., description="AWS Account ID to query"),
    region: str = Query(..., description="AWS region, e.g. us-east-1")
):
    service = service.lower()
    if service not in MONITORING_SERVICES:
        raise HTTPException(status_code=400, detail=f"Unsupported service '{service}'. Supported: {MONITORING_SERVICES}")
    
    session = get_boto3_session_for_account(account_id)
    try:
        if service == "cloudwatch":
            logs = list_cloudwatch_log_groups(session, account_id, region)
            alarms = list_cloudwatch_alarms(session, account_id, region)
            data = {
                "log_groups": [lg.dict() for lg in logs],
                "alarms": [a.dict() for a in alarms]
            }
            total = len(data["log_groups"]) + len(data["alarms"])
        elif service == "cloudtrail":
            trails = list_cloudtrail_trails(session, account_id, region)
            data = {"trails": [t.dict() for t in trails]}
            total = len(data["trails"])
        elif service == "xray":
            groups = list_xray_groups(session, account_id, region)
            traces = list_xray_traces(session, account_id, region)
            data = {
                "groups": [g.dict() for g in groups],
                "traces": [t.dict() for t in traces]
            }
            total = len(data["groups"]) + len(data["traces"])
        else:
            data = {}
            total = 0
        
        return StandardResponse(
            status="success",
            message=f"Retrieved {total} {service} resources",
            data=data,
            errors=None,
            metadata={"total_count": total, "service": service, "account_id": account_id, "region": region}
        )
    except HTTPException as e:
        # pass-through already created HTTPException
        raise e
    except Exception as e:
        logger.exception("Unexpected error in list_monitoring_resources")
        raise handle_aws_error(e, f"list_monitoring_resources:{service}")


@router.post(
    "/monitoring/{service}",
    response_model=StandardResponse,
    summary="Get detailed resource info for a monitoring service",
    description="Return detailed resource information, security findings, and recommendations for provided resource IDs",
    responses={
        200: {
            "description": "Successful response with detailed resources",
            "content": {
                "application/json": {
                    "examples": {
                        "cloudwatch_detail": {
                            "summary": "CloudWatch Log Group Detail Example",
                            "value": {
                                "status": "success",
                                "message": "Retrieved details for 2 resources",
                                "data": [
                                    {
                                        "logGroupName": "/aws/lambda/my-function",
                                        "creationTime": "2021-07-01T00:00:00",
                                        "retentionInDays": 30,
                                        "storedBytes": 1073741824,
                                        "arn": "arn:aws:logs:us-east-1:123456789012:log-group:/aws/lambda/my-function",
                                        "metricFilterCount": 2,
                                        "subscriptionFilters": [],
                                        "kmsKeyId": None,
                                        "tags": {},
                                        "recommendations": [],
                                        "security_findings": [
                                            {
                                                "type": "security",
                                                "severity": "high",
                                                "message": "Log group not encrypted with KMS",
                                                "recommendation": "Enable KMS encryption for log group to protect sensitive data at rest"
                                            }
                                        ]
                                    }
                                ],
                                "metadata": {"service": "cloudwatch", "account_id": "123456789012", "region": "us-east-1", "requested": 2}
                            }
                        }
                    }
                }
            }
        },
        400: {"description": "Validation error or bad request"},
        404: {"description": "Resource not found"},
        500: {"description": "Internal server error"}
    }
)
async def get_monitoring_resource_details(
    service: str,
    payload: ResourceIdsRequest = Body(...),
    account_id: str = Query(..., description="AWS Account ID to query"),
    region: str = Query(..., description="AWS region, e.g. us-east-1")
):
    service = service.lower()
    if service not in MONITORING_SERVICES:
        raise HTTPException(status_code=400, detail=f"Unsupported service '{service}'. Supported: {MONITORING_SERVICES}")
    
    session = get_boto3_session_for_account(account_id)
    errors: List[str] = []
    results: List[Dict[str, Any]] = []
    
    try:
        if service == "cloudwatch":
            logs_client = session.client("logs", region_name=region)
            cw_client = session.client("cloudwatch", region_name=region)
            # For each resource id, try to detect whether it's a log group or alarm
            for rid in payload.resource_ids:
                # Try log group
                try:
                    lg_detail = analyze_cloudwatch_log_group(logs_client, rid, account_id)
                    results.append(lg_detail.dict())
                    continue
                except HTTPException as e:
                    # if not found as log group, try alarm as fallback
                    if e.status_code != 404:
                        errors.append(f"{rid}: {e.detail}")
                        continue
                
                # Try alarm
                try:
                    alarm_detail = analyze_cloudwatch_alarm(cw_client, rid)
                    results.append(alarm_detail.dict())
                    continue
                except HTTPException as e:
                    errors.append(f"{rid}: {e.detail}")
                    continue
        
        elif service == "cloudtrail":
            ct_client = session.client("cloudtrail", region_name=region)
            for rid in payload.resource_ids:
                try:
                    detail = analyze_cloudtrail_trail(ct_client, rid)
                    results.append(detail.dict())
                except HTTPException as e:
                    errors.append(f"{rid}: {e.detail}")
                    continue
        
        elif service == "xray":
            xray_client = session.client("xray", region_name=region)
            for rid in payload.resource_ids:
                # Try group first
                try:
                    detail = analyze_xray_group(xray_client, rid)
                    results.append(detail.dict())
                    continue
                except HTTPException as e:
                    if e.status_code != 404:
                        errors.append(f"{rid}: {e.detail}")
                        continue
                
                # If not a group, attempt to retrieve trace summary by id (best effort)
                try:
                    # attempt get_trace_summaries with filter expression for id
                    # Note: X-Ray API doesn't have direct get_trace by id in this scope; this is best-effort
                    response = xray_client.batch_get_traces(TraceIds=[rid])
                    traces = response.get("Traces", [])
                    if traces:
                        # convert a trace to basic summary-like structure
                        t = traces[0]
                        trace_summary = {
                            "Id": t.get("Id", rid),
                            "StartTime": t.get("Segments", [{}])[0].get("StartTime"),
                            "Duration": t.get("Segments", [{}])[0].get("Document", {}).get("duration", 0) if t.get("Segments") else 0,
                            "ResponseStatus": 0,
                            "HasError": False,
                            "HasFault": False,
                            "HasThrottle": False
                        }
                        results.append(trace_summary)
                    else:
                        errors.append(f"{rid}: X-Ray group/trace not found")
                except ClientError as e:
                    errors.append(f"{rid}: {str(e)}")
                    continue
        
        # Build metadata
        metadata = {"service": service, "account_id": account_id, "region": region, "requested": len(payload.resource_ids), "returned": len(results)}
        
        status = "success" if results else "error"
        message = f"Retrieved details for {len(results)} resources" if results else "No resource details retrieved"
        
        return StandardResponse(
            status=status,
            message=message,
            data=results if results else None,
            errors=errors if errors else None,
            metadata=metadata
        )
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.exception("Unexpected error in get_monitoring_resource_details")
        raise handle_aws_error(e, f"get_monitoring_resource_details:{service}")