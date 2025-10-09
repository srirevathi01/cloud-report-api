from fastapi import APIRouter, Request, HTTPException, Query, Body
from pydantic import BaseModel, Field
from typing import Dict, Any, List
import logging, time
from botocore.exceptions import ClientError

router = APIRouter()
logger = logging.getLogger(__name__)

# ----------------- Monitoring Services -----------------
MONITOR_SERVICES = [
    "cloudwatch_alarms",
    "cloudwatch_logs",
    "cloudwatch_dashboards",
    "cloudtrail",
    "config",
    "xray"
]

# ----------------- Cache -----------------
CACHE_MON: Dict[Any, Dict[str, Any]] = {}
CACHE_TTL = 300  # seconds

def get_mon_cache(account_id: str, region: str, service: str):
    key = (account_id, region, service)
    entry = CACHE_MON.get(key)
    if entry and (time.time() - entry["timestamp"] < CACHE_TTL):
        return entry["data"]
    return None

def set_mon_cache(account_id: str, region: str, service: str, data: Any):
    key = (account_id, region, service)
    CACHE_MON[key] = {"data": data, "timestamp": time.time()}


# ----------------- Pydantic Models -----------------
class ResourceDetailRequest(BaseModel):
    resource_id: str

class MonitoringListResponse(BaseModel):
    monitoring_services: List[str]

class ServiceListResponse(BaseModel):
    account_id: str
    region: str
    service: str
    resources: List[Dict[str, Any]] = Field(default_factory=list)
    total: int

class ResourceDetailResponse(BaseModel):
    account_id: str
    region: str
    service: str
    resource: str
    details: Dict[str, Any]


# ----------------- Paginator Functions -----------------

def list_cloudwatch_alarms(session, account_id: str, region: str) -> List[Dict[str, Any]]:
    cached = get_mon_cache(account_id, region, "cloudwatch_alarms")
    if cached:
        return cached

    cw = session.client("cloudwatch", region_name=region)
    alarms = []

    paginator = cw.get_paginator("describe_alarms")
    for page in paginator.paginate():
        for a in page.get("MetricAlarms", []):
            # Alarm state history
            state_history = cw.describe_alarm_history(AlarmName=a["AlarmName"], HistoryItemType='StateUpdate')['AlarmHistoryItems']
            last_triggered = state_history[0]['Timestamp'] if state_history else None
            # Categorize severity
            severity = "High" if a.get("StateValue") == "ALARM" else "Medium"

            alarms.append({
                "AlarmName": a["AlarmName"],
                "State": a.get("StateValue"),
                "LastUpdated": str(a.get("StateUpdatedTimestamp")),
                "LastTriggered": str(last_triggered),
                "Actions": a.get("AlarmActions", []),
                "OKActions": a.get("OKActions", []),
                "Threshold": a.get("Threshold"),
                "Namespace": a.get("Namespace"),
                "MetricName": a.get("MetricName"),
                "Severity": severity
            })

    set_mon_cache(account_id, region, "cloudwatch_alarms", alarms)
    return alarms

def list_cloudwatch_logs(session, account_id: str, region: str) -> List[Dict[str, Any]]:
    cached = get_mon_cache(account_id, region, "cloudwatch_logs")
    if cached:
        return cached

    logs_client = session.client("logs", region_name=region)
    log_groups = []

    paginator = logs_client.get_paginator("describe_log_groups")
    for page in paginator.paginate():
        for lg in page.get("logGroups", []):
            try:
                # Subscription filters
                filters = logs_client.describe_subscription_filters(
                    logGroupName=lg["logGroupName"]
                ).get("subscriptionFilters", [])

                # Recent ingestion metrics (bytes in last 1 hour)
                metric_data = logs_client.get_metric_statistics(
                    Namespace="AWS/Logs",
                    MetricName="IncomingBytes",
                    Dimensions=[{"Name": "LogGroupName", "Value": lg["logGroupName"]}],
                    StartTime=int(time.time()) - 3600,
                    EndTime=int(time.time()),
                    Period=3600,
                    Statistics=["Sum"]
                )
                datapoints = metric_data.get("Datapoints", [])
                ingestion_bytes = datapoints[0].get('Sum', 0) if datapoints else 0

                log_groups.append({
                    "LogGroupName": lg["logGroupName"],
                    "RetentionInDays": lg.get("retentionInDays"),
                    "StoredBytes": lg.get("storedBytes"),
                    "Arn": lg.get("arn"),
                    "SubscriptionFilters": [f["filterName"] for f in filters],
                    "LogStreamCount": len(filters),
                    "RecentIngestionBytes": ingestion_bytes,
                    "HasErrors": lg.get("storedBytes", 0) > 0
                })
            except Exception as e:
                logger.error(f"Error processing log group {lg['logGroupName']}: {e}")

    set_mon_cache(account_id, region, "cloudwatch_logs", log_groups)
    return log_groups

def list_cloudwatch_dashboards(session, account_id: str, region: str) -> List[Dict[str, Any]]:
    cached = get_mon_cache(account_id, region, "cloudwatch_dashboards")
    if cached:
        return cached

    cw = session.client("cloudwatch", region_name=region)
    dashboards = []

    paginator = cw.get_paginator("list_dashboards")
    for page in paginator.paginate():
        for d in page.get("DashboardEntries", []):
            details = cw.get_dashboard(DashboardName=d["DashboardName"])["DashboardBody"]
            dashboards.append({
                "DashboardName": d["DashboardName"],
                "LastModified": str(d.get("LastModified")),
                "Size": d.get("Size", 0),
                "DashboardArn": d.get("DashboardArn"),
                "Environment": "prod" if "prod" in d["DashboardName"].lower() else "dev",
                "WidgetCount": details.count("metrics"),
                "LinkedMetrics": details  # Could parse JSON to list metrics
            })

    set_mon_cache(account_id, region, "cloudwatch_dashboards", dashboards)
    return dashboards


def list_cloudtrail_trails(session, account_id: str, region: str) -> List[Dict[str, Any]]:
    cached = get_mon_cache(account_id, region, "cloudtrail")
    if cached:
        return cached

    ct = session.client("cloudtrail", region_name=region)
    trails = []

    paginator = ct.get_paginator("describe_trails")
    for page in paginator.paginate():
        for t in page.get("trailList", []):
            trails.append({
                "Name": t["Name"],
                "S3Bucket": t.get("S3BucketName"),
                "IsLogging": t.get("IsLogging"),
                "IsMultiRegionTrail": t.get("IsMultiRegionTrail"),
                "KMSKeyId": t.get("KmsKeyId"),
                "IncludeGlobalServiceEvents": t.get("IncludeGlobalServiceEvents", False),
                "InsightEventsEnabled": t.get("IncludeInsightEvents", False)
            })

    set_mon_cache(account_id, region, "cloudtrail", trails)
    return trails


def list_config_rules(session, account_id: str, region: str) -> List[Dict[str, Any]]:
    cached = get_mon_cache(account_id, region, "config")
    if cached:
        return cached

    cfg = session.client("config", region_name=region)
    rules = []

    paginator = cfg.get_paginator("describe_config_rules")
    for page in paginator.paginate():
        for r in page.get("ConfigRules", []):
            rules.append({
                "ConfigRuleName": r["ConfigRuleName"],
                "Compliance": r.get("Compliance", {}).get("ComplianceType"),
                "LastEvaluated": str(r.get("LastSuccessfulEvaluationTime")),
                "Scope": r.get("Scope"),
                "AutomationActions": r.get("AutomationActions"),
                "Owner": r.get("Source", {}).get("Owner")
            })

    set_mon_cache(account_id, region, "config", rules)
    return rules


def list_xray_groups(session, account_id: str, region: str) -> List[Dict[str, Any]]:
    cached = get_mon_cache(account_id, region, "xray")
    if cached:
        return cached

    xray = session.client("xray", region_name=region)
    groups = []

    paginator = xray.get_paginator("get_groups")
    for page in paginator.paginate():
        for g in page.get("Groups", []):
            groups.append({
                "GroupName": g["GroupName"],
                "ServiceMap": g.get("ServiceIds"),
                "TraceCount": g.get("ApproximateTraceCount"),
                "RecentErrors": g.get("ErrorStatistics"),
                "SamplingRule": g.get("SamplingRuleRecord"),
                "AverageLatency": g.get("AverageResponseTime", 0)
            })

    set_mon_cache(account_id, region, "xray", groups)
    return groups


# ----------------- Detailed Analysis Functions -----------------

def analyze_cloudwatch_alarm(cw_client, alarm_name: str) -> Dict[str, Any]:
    alarm = cw_client.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"][0]
    state_history = cw_client.describe_alarm_history(AlarmName=alarm_name, HistoryItemType='StateUpdate')['AlarmHistoryItems']
    last_triggered = state_history[0]['Timestamp'] if state_history else None
    severity = "High" if alarm.get("StateValue")=="ALARM" else "Medium"

    recommendations = []
    if not alarm.get("AlarmActions"):
        recommendations.append({"type":"notification","severity":"medium","message":"Alarm has no SNS actions"})
    if alarm.get("StateValue")=="ALARM":
        recommendations.append({"type":"alert","severity":"high","message":"Alarm currently active"})

    return {"configuration": {**alarm, "LastTriggered": str(last_triggered), "Severity": severity}, "recommendations": recommendations}

def analyze_cloudwatch_log(log_client, log_group_name: str) -> Dict[str, Any]:
    log_group = log_client.describe_log_groups(logGroupNamePrefix=log_group_name).get("logGroups", [])
    if log_group:
        lg = log_group[0]
        filters = log_client.describe_subscription_filters(logGroupName=lg["logGroupName"]).get("subscriptionFilters", [])
        return {
            "configuration": {
                "LogGroupName": lg["logGroupName"],
                "RetentionInDays": lg.get("retentionInDays"),
                "StoredBytes": lg.get("storedBytes"),
                "SubscriptionFilters": [f["filterName"] for f in filters]
            },
            "recommendations": []
        }
    return {"configuration": {"LogGroupName": log_group_name}, "recommendations": []}


def analyze_cloudtrail_trail(ct_client, trail_name: str) -> Dict[str, Any]:
    trail = ct_client.describe_trails(trailNameList=[trail_name])["trailList"][0]
    recommendations = []
    if not trail.get("IsLogging"):
        recommendations.append({"type":"security","severity":"high","message":"Trail logging not enabled"})
    if not trail.get("KmsKeyId"):
        recommendations.append({"type":"availability","severity":"medium","message":"Trail not encrypted"})
    return {"configuration": trail, "recommendations": recommendations}


def analyze_config_rule(cfg_client, rule_name: str) -> Dict[str, Any]:
    rule = cfg_client.describe_config_rules(ConfigRuleNames=[rule_name])["ConfigRules"][0]
    recommendations = []
    if rule.get("ConfigRuleState") != "ACTIVE":
        recommendations.append({"type":"compliance","severity":"medium","message":"Rule is not active"})
    return {"configuration": rule, "recommendations": recommendations}


def analyze_xray_group(xray_client, group_name: str) -> Dict[str, Any]:
    group = xray_client.get_groups(GroupNames=[group_name])["Groups"][0]
    return {"configuration": group, "recommendations": []}


# ----------------- API Routes -----------------

@router.get("/monitoring", response_model=MonitoringListResponse)
async def list_monitoring_services(account_id: str = Query(...), region: str = Query("us-east-1")):
    return MonitoringListResponse(monitoring_services=MONITOR_SERVICES)


@router.get("/monitoring/{service}", response_model=ServiceListResponse)
async def list_monitoring_service(service: str, request: Request, account_id: str = Query(...), region: str = Query("us-east-1")):
    if service not in MONITOR_SERVICES:
        raise HTTPException(404, f"Service {service} not supported")
    session = getattr(request.state, "session", None)
    if not session:
        raise HTTPException(401, "AWS session not found")

    func_map = {
        "cloudwatch_alarms": list_cloudwatch_alarms,
        "cloudwatch_logs": list_cloudwatch_logs,
        "cloudwatch_dashboards": list_cloudwatch_dashboards,
        "cloudtrail": list_cloudtrail_trails,
        "config": list_config_rules,
        "xray": list_xray_groups
    }

    resources = func_map[service](session, account_id, region)
    return ServiceListResponse(account_id=account_id, region=region, service=service, resources=resources, total=len(resources))


@router.post("/monitoring/{service}/detail", response_model=ResourceDetailResponse)
async def get_monitoring_detail(service: str, request: Request, payload: ResourceDetailRequest = Body(...), account_id: str = Query(...), region: str = Query("us-east-1")):
    if service not in MONITOR_SERVICES:
        raise HTTPException(404, f"Service {service} not supported")
    session = getattr(request.state, "session", None)
    if not session:
        raise HTTPException(401, "AWS session not found")

    func_map = {
        "cloudwatch_alarms": analyze_cloudwatch_alarm,
        "cloudtrail": analyze_cloudtrail_trail,
        "config": analyze_config_rule,
        "xray": analyze_xray_group,
        "cloudwatch_logs": analyze_cloudwatch_log,
        "cloudwatch_dashboards": analyze_cloudwatch_dashboard
    }

    list_map = {
        "cloudwatch_alarms": list_cloudwatch_alarms,
        "cloudtrail": list_cloudtrail_trails,
        "config": list_config_rules,
        "xray": list_xray_groups,
        "cloudwatch_logs": list_cloudwatch_logs,
        "cloudwatch_dashboards": list_cloudwatch_dashboards
    }

    # Check if resource exists
    resources = list_map[service](session, account_id, region)
    resource_names = [r.get("AlarmName") or r.get("Name") or r.get("LogGroupName") or r.get("DashboardName") or r.get("ConfigRuleName") or r.get("GroupName") for r in resources]

    if payload.resource_id not in resource_names:
        raise HTTPException(404, f"{service} resource '{payload.resource_id}' not found")

    # Detailed analysis
    if service in func_map:
        details = func_map[service](
            session.client(service.replace("_metrics", "").replace("_alarms", "").replace("_logs", ""), region_name=region),
            payload.resource_id
        )
    else:
        details = {"configuration": {"name": payload.resource_id}, "recommendations": []}

    return ResourceDetailResponse(
        account_id=account_id,
        region=region,
        service=service,
        resource=payload.resource_id,
        details=details
    )
