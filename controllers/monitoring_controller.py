from fastapi import APIRouter, Request, HTTPException, Query
from pydantic import BaseModel, Field
from typing import Dict, Any, List
import logging, time

router = APIRouter()
logger = logging.getLogger(__name__)


MONITOR_SERVICES = [
    "cloudwatch_metrics",
    "cloudwatch_alarms",
    "cloudwatch_logs",
    "cloudwatch_dashboards",
    "cloudtrail",
    "config",
    "xray"
]

# Cache
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


# Pydantic Models
class ResourceDetailRequest(BaseModel):
    resource_id: str

class MonitoringListResponse(BaseModel):
    account_id: str
    region: str
    cloudwatch_metrics: List[str] = Field(default_factory=list)
    cloudwatch_alarms: List[str] = Field(default_factory=list)
    cloudwatch_logs: List[str] = Field(default_factory=list)
    cloudwatch_dashboards: List[str] = Field(default_factory=list)
    cloudtrail: List[str] = Field(default_factory=list)
    config: List[str] = Field(default_factory=list)
    xray: List[str] = Field(default_factory=list)

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
    details: Dict[str, Any]

class CloudDashboardResponse(BaseModel):
    account_id: str
    region: str
    total_metrics: int
    total_alarms: int
    total_logs: int
    total_dashboards: int
    total_trails: int
    total_config_rules: int
    total_xray_groups: int
    details: Dict[str, List[str]]
    summary: Dict[str, Any]

# Paginator Functions
def list_cloudwatch_metrics(session, account_id: str, region: str) -> List[str]:
    cached = get_mon_cache(account_id, region, "cloudwatch_metrics")
    if cached: return cached
    cw = session.client("cloudwatch", region_name=region)
    metrics = []
    paginator = cw.get_paginator("list_metrics")
    for page in paginator.paginate():
        for m in page.get("Metrics", []):
            metrics.append(f"{m['Namespace']}:{m['MetricName']}")
    set_mon_cache(account_id, region, "cloudwatch_metrics", metrics)
    return metrics

def list_cloudwatch_alarms(session, account_id: str, region: str) -> List[str]:
    cached = get_mon_cache(account_id, region, "cloudwatch_alarms")
    if cached: return cached
    cw = session.client("cloudwatch", region_name=region)
    alarms = []
    paginator = cw.get_paginator("describe_alarms")
    for page in paginator.paginate():
        for a in page.get("MetricAlarms", []):
            alarms.append(a["AlarmName"])
    set_mon_cache(account_id, region, "cloudwatch_alarms", alarms)
    return alarms

def list_cloudwatch_logs(session, account_id: str, region: str) -> List[str]:
    cached = get_mon_cache(account_id, region, "cloudwatch_logs")
    if cached: return cached
    logs = session.client("logs", region_name=region)
    log_groups = []
    paginator = logs.get_paginator("describe_log_groups")
    for page in paginator.paginate():
        for lg in page.get("logGroups", []):
            log_groups.append(lg["logGroupName"])
    set_mon_cache(account_id, region, "cloudwatch_logs", log_groups)
    return log_groups

def list_cloudwatch_dashboards(session, account_id: str, region: str) -> List[str]:
    cached = get_mon_cache(account_id, region, "cloudwatch_dashboards")
    if cached: return cached
    cw = session.client("cloudwatch", region_name=region)
    try:
        dashboards = cw.list_dashboards()
        dashboard_names = [d["DashboardName"] for d in dashboards.get("DashboardEntries", [])]
    except ClientError as e:
        logger.error(f"Error fetching CloudWatch dashboards: {e}")
        dashboard_names = []
    set_mon_cache(account_id, region, "cloudwatch_dashboards", dashboard_names)
    return dashboard_names

def list_cloudtrail_trails(session, account_id: str, region: str) -> List[str]:
    cached = get_mon_cache(account_id, region, "cloudtrail")
    if cached: 
        return cached
    ct = session.client("cloudtrail", region_name=region)
    trails = []
    try:
        paginator = ct.get_paginator("describe_trails")
        for page in paginator.paginate():
            for t in page.get("trailList", []):
                trails.append(t["Name"])
    except ct.exceptions.OperationNotPermittedException:
        # fallback — some regions or accounts don’t support paginator
        resp = ct.describe_trails()
        for t in resp.get("trailList", []):
            trails.append(t["Name"])
    except Exception as e:
        # Handle the specific case where pagination is unsupported
        if "cannot be paginated" in str(e):
            resp = ct.describe_trails()
            for t in resp.get("trailList", []):
                trails.append(t["Name"])
        else:
            logger.error(f"Error listing CloudTrail trails: {e}")
            trails = []
    set_mon_cache(account_id, region, "cloudtrail", trails)
    return trails

def list_config_rules(session, account_id: str, region: str) -> List[str]:
    cached = get_mon_cache(account_id, region, "config")
    if cached: return cached
    cfg = session.client("config", region_name=region)
    rules = []
    paginator = cfg.get_paginator("describe_config_rules")
    for page in paginator.paginate():
        for r in page.get("ConfigRules", []):
            rules.append(r["ConfigRuleName"])
    set_mon_cache(account_id, region, "config", rules)
    return rules

def list_xray_groups(session, account_id: str, region: str) -> List[str]:
    cached = get_mon_cache(account_id, region, "xray")
    if cached: return cached
    xray = session.client("xray", region_name=region)
    groups = []
    paginator = xray.get_paginator("get_groups")
    for page in paginator.paginate():
        for g in page.get("Groups", []):
            groups.append(g["GroupName"])
    set_mon_cache(account_id, region, "xray", groups)
    return groups


# Detailed Analysis Functions

def analyze_cloudwatch_alarm(cw_client, alarm_name: str) -> Dict[str, Any]:
    alarm = cw_client.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"][0]
    recommendations = []
    if not alarm.get("OKActions") and not alarm.get("AlarmActions"):
        recommendations.append({"type":"notification","severity":"medium","message":"Alarm has no SNS actions"})
    return {"configuration": alarm, "recommendations": recommendations}

def analyze_cloudtrail_trail(ct_client, trail_name: str) -> Dict[str, Any]:
    trail = ct_client.describe_trails(trailNameList=[trail_name])["trailList"][0]
    recommendations = []
    if not trail.get("IsLogging"):
        recommendations.append({"type":"security","severity":"high","message":"Trail logging not enabled"})
    if not trail.get("IsMultiRegionTrail"):
        recommendations.append({"type":"availability","severity":"medium","message":"Trail not multi-region"})
    return {"configuration": trail, "recommendations": recommendations}

def analyze_config_rule(cfg_client, rule_name: str) -> Dict[str, Any]:
    rule = cfg_client.describe_config_rules(ConfigRuleNames=[rule_name])["ConfigRules"][0]
    recommendations = []
    if not rule.get("Source"):
        recommendations.append({"type":"security","severity":"high","message":"Rule source not defined"})
    return {"configuration": rule, "recommendations": recommendations}

def analyze_xray_group(xray_client, group_name: str) -> Dict[str, Any]:
    group = xray_client.get_groups(GroupNames=[group_name])["Groups"][0]
    recommendations = []
    return {"configuration": group, "recommendations": recommendations}


# API Routes
@router.get("/monitoring", response_model=MonitoringListResponse)
async def list_all_monitoring(request: Request, account_id: str = Query(...), region: str = Query("us-east-1")):
    session = getattr(request.state, "session", None)
    if not session: raise HTTPException(401, "AWS session not found")
    return MonitoringListResponse(
        account_id=account_id,
        region=region,
        cloudwatch_metrics=list_cloudwatch_metrics(session, account_id, region),
        cloudwatch_alarms=list_cloudwatch_alarms(session, account_id, region),
        cloudwatch_logs=list_cloudwatch_logs(session, account_id, region),
        cloudwatch_dashboards=list_cloudwatch_dashboards(session, account_id, region),
        cloudtrail=list_cloudtrail_trails(session, account_id, region),
        config=list_config_rules(session, account_id, region),
        xray=list_xray_groups(session, account_id, region)
    )

@router.get("/monitoring/{service}", response_model=ServiceListResponse)
async def list_monitoring_service(service: str, request: Request, account_id: str = Query(...), region: str = Query("us-east-1")):
    if service not in MONITOR_SERVICES: raise HTTPException(404, f"Service {service} not supported")
    session = getattr(request.state, "session", None)
    if not session: raise HTTPException(401, "AWS session not found")
    func_map = {
        "cloudwatch_metrics": list_cloudwatch_metrics,
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
async def get_monitoring_detail(service: str, request: Request, payload: ResourceDetailRequest, account_id: str = Query(...), region: str = Query("us-east-1")):
    if service not in MONITOR_SERVICES: raise HTTPException(404, f"Service {service} not supported")
    session = getattr(request.state, "session", None)
    if not session: raise HTTPException(401, "AWS session not found")

    func_map = {
        "cloudwatch_alarms": analyze_cloudwatch_alarm,
        "cloudtrail": analyze_cloudtrail_trail,
        "config": analyze_config_rule,
        "xray": analyze_xray_group
    }

    list_map = {
        "cloudwatch_alarms": list_cloudwatch_alarms,
        "cloudtrail": list_cloudtrail_trails,
        "config": list_config_rules,
        "xray": list_xray_groups,
        "cloudwatch_metrics": list_cloudwatch_metrics,
        "cloudwatch_logs": list_cloudwatch_logs,
        "cloudwatch_dashboards": list_cloudwatch_dashboards
    }

    # check if resource exists
    resources = list_map[service](session, account_id, region)
    if payload.resource_id not in resources:
        raise HTTPException(404, f"{service} resource '{payload.resource_id}' not found")
 
    # detailed config + recommendations
    if service in func_map:
        details = func_map[service](session.client(service.replace("_metrics","").replace("_alarms","").replace("_logs",""), region_name=region), payload.resource_id)
    else:
        # metrics/log groups: no detailed analysis, just name
        details = {"configuration": {"name": payload.resource_id}, "recommendations": []}
 
    return ResourceDetailResponse(account_id=account_id, region=region, service=service, resource=payload.resource_id, details=details)
