from fastapi import APIRouter, Request, HTTPException, Query, Body
from pydantic import BaseModel, Field
from typing import Dict, Any, List
import logging, time, json
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

# ----------------- Helpers -----------------
def service_to_client_name(service: str) -> str:
    if service == "cloudwatch_logs":
        return "logs"
    if service.startswith("cloudwatch"):
        return "cloudwatch"
    return service

def safe_get_first(datapoints: List[Dict[str, Any]], key: str, default=0):
    if not datapoints:
        return default
    return datapoints[0].get(key, default)

# ----------------- LIST / METADATA FUNCTIONS -----------------
def list_cloudwatch_alarms(session, account_id: str, region: str) -> List[Dict[str, Any]]:
    cached = get_mon_cache(account_id, region, "cloudwatch_alarms")
    if cached:
        return cached
    cw = session.client("cloudwatch", region_name=region)
    alarms = []
    try:
        paginator = cw.get_paginator("describe_alarms")
        for page in paginator.paginate():
            for a in page.get("MetricAlarms", []):
                alarms.append({"AlarmName": a.get("AlarmName")})
    except Exception as e:
        logger.error(f"Error listing CloudWatch alarms: {e}")
    set_mon_cache(account_id, region, "cloudwatch_alarms", alarms)
    return alarms

def list_cloudwatch_logs(session, account_id: str, region: str) -> List[Dict[str, Any]]:
    cached = get_mon_cache(account_id, region, "cloudwatch_logs")
    if cached:
        return cached
    logs_client = session.client("logs", region_name=region)
    logs = []
    try:
        paginator = logs_client.get_paginator("describe_log_groups")
        for page in paginator.paginate():
            for lg in page.get("logGroups", []):
                logs.append({"LogGroupName": lg.get("logGroupName")})
    except Exception as e:
        logger.error(f"Error listing CloudWatch logs: {e}")
    set_mon_cache(account_id, region, "cloudwatch_logs", logs)
    return logs

def list_cloudwatch_dashboards(session, account_id: str, region: str) -> List[Dict[str, Any]]:
    cached = get_mon_cache(account_id, region, "cloudwatch_dashboards")
    if cached:
        return cached
    cw = session.client("cloudwatch", region_name=region)
    dashboards = []
    try:
        paginator = cw.get_paginator("list_dashboards")
        for page in paginator.paginate():
            for d in page.get("DashboardEntries", []):
                dashboards.append({"DashboardName": d.get("DashboardName")})
    except Exception as e:
        logger.error(f"Error listing dashboards: {e}")
    set_mon_cache(account_id, region, "cloudwatch_dashboards", dashboards)
    return dashboards

def list_cloudtrail_trails(session, account_id: str, region: str) -> List[Dict[str, Any]]:
    cached = get_mon_cache(account_id, region, "cloudtrail")
    if cached:
        return cached
    ct = session.client("cloudtrail", region_name=region)
    trails = []
    try:
        paginator = ct.get_paginator("describe_trails")
        for page in paginator.paginate():
            for t in page.get("trailList", []):
                trails.append({"Name": t.get("Name")})
    except Exception as e:
        logger.error(f"Error listing CloudTrail trails: {e}")
    set_mon_cache(account_id, region, "cloudtrail", trails)
    return trails

def list_config_rules(session, account_id: str, region: str) -> List[Dict[str, Any]]:
    cached = get_mon_cache(account_id, region, "config")
    if cached:
        return cached
    cfg = session.client("config", region_name=region)
    rules = []
    try:
        paginator = cfg.get_paginator("describe_config_rules")
        for page in paginator.paginate():
            for r in page.get("ConfigRules", []):
                rules.append({"ConfigRuleName": r.get("ConfigRuleName")})
    except Exception as e:
        logger.error(f"Error listing config rules: {e}")
    set_mon_cache(account_id, region, "config", rules)
    return rules

def list_xray_groups(session, account_id: str, region: str) -> List[Dict[str, Any]]:
    cached = get_mon_cache(account_id, region, "xray")
    if cached:
        return cached
    xray = session.client("xray", region_name=region)
    groups = []
    try:
        paginator = xray.get_paginator("get_groups")
        for page in paginator.paginate():
            for g in page.get("Groups", []):
                groups.append({"GroupName": g.get("GroupName")})
    except Exception as e:
        logger.error(f"Error listing X-Ray groups: {e}")
    set_mon_cache(account_id, region, "xray", groups)
    return groups

# ----------------- DETAILED ANALYZERS -----------------
def analyze_cloudwatch_alarm(cw_client, alarm_name: str) -> Dict[str, Any]:
    alarm = {}
    try:
        alarm = cw_client.describe_alarms(AlarmNames=[alarm_name]).get("MetricAlarms", [])[0]
    except Exception:
        pass
    return {"configuration": alarm, "recommendations": []}

def analyze_cloudwatch_log(log_client, log_group_name: str) -> Dict[str, Any]:
    return {"configuration": {"LogGroupName": log_group_name}, "recommendations": []}

def analyze_cloudwatch_dashboard(cw_client, dashboard_name: str) -> Dict[str, Any]:
    return {"configuration": {"DashboardName": dashboard_name}, "recommendations": []}

def analyze_cloudtrail_trail(ct_client, trail_name: str) -> Dict[str, Any]:
    return {"configuration": {"TrailName": trail_name}, "recommendations": []}

def analyze_config_rule(cfg_client, rule_name: str) -> Dict[str, Any]:
    return {"configuration": {"ConfigRuleName": rule_name}, "recommendations": []}

def analyze_xray_group(xray_client, group_name: str) -> Dict[str, Any]:
    return {"configuration": {"GroupName": group_name}, "recommendations": []}

# ----------------- API ROUTES -----------------
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
async def get_monitoring_detail(
    service: str,
    request: Request,
    payload: ResourceDetailRequest = Body(...),
    account_id: str = Query(...),
    region: str = Query("us-east-1")
):
    if service not in MONITOR_SERVICES:
        raise HTTPException(404, f"Service {service} not supported")
    session = getattr(request.state, "session", None)
    if not session:
        raise HTTPException(401, "AWS session not found")

    analyzer_map = {
        "cloudwatch_alarms": analyze_cloudwatch_alarm,
        "cloudwatch_logs": analyze_cloudwatch_log,
        "cloudwatch_dashboards": analyze_cloudwatch_dashboard,
        "cloudtrail": analyze_cloudtrail_trail,
        "config": analyze_config_rule,
        "xray": analyze_xray_group
    }

    list_map = {
        "cloudwatch_alarms": list_cloudwatch_alarms,
        "cloudwatch_logs": list_cloudwatch_logs,
        "cloudwatch_dashboards": list_cloudwatch_dashboards,
        "cloudtrail": list_cloudtrail_trails,
        "config": list_config_rules,
        "xray": list_xray_groups
    }

    resources = list_map[service](session, account_id, region)
    resource_names = [
        r.get("AlarmName") or r.get("Name") or r.get("LogGroupName")
        or r.get("DashboardName") or r.get("ConfigRuleName") or r.get("GroupName")
        for r in resources
    ]

    if payload.resource_id not in resource_names:
        raise HTTPException(404, f"{service} resource '{payload.resource_id}' not found")

    analyzer = analyzer_map[service]
    client_name = service_to_client_name(service)
    client = session.client(client_name, region_name=region)
    details = analyzer(client, payload.resource_id)

    return ResourceDetailResponse(
        account_id=account_id,
        region=region,
        service=service,
        resource=payload.resource_id,
        details=details
    )