from fastapi import APIRouter, Request, Query
from typing import Optional, List
from botocore.exceptions import ClientError

router = APIRouter()


# --- GET /monitoring ---
@router.get("/monitoring")
def list_monitoring_services(request: Request):
    """List all monitoring services supported by the API."""
    try:
        _ = request.state.session
        services = [
            "cloudwatch-logs",
            "cloudwatch-alarms",
            "cloudwatch-dashboards",
            "cloudtrail",
            "xray",
            "config",
            "sns"
        ]
        return {"monitoring_services": services}
    except Exception as e:
        return {"error": str(e)}


# --- Generic /list endpoint for all monitoring services ---
@router.get("/monitoring/{service_name}/list")
def list_service_resources(
    service_name: str,
    request: Request,
    region: str = Query("us-east-1"),
):
    """List all resources under a specific monitoring service."""
    try:
        creds = request.state.session
        service_name = service_name.lower()
        resources = []

        if service_name == "cloudwatch-logs":
            logs_client = creds.client("logs", region_name=region)
            resp = logs_client.describe_log_groups()
            resources = resp.get("logGroups", [])

        elif service_name == "cloudwatch-dashboards":
            cw_client = creds.client("cloudwatch", region_name=region)
            resp = cw_client.list_dashboards()
            resources = resp.get("DashboardEntries", [])

        elif service_name == "cloudwatch-alarms":
            cw_client = creds.client("cloudwatch", region_name=region)
            resp = cw_client.describe_alarms()
            resources = resp.get("MetricAlarms", [])

        elif service_name == "cloudtrail":
            ct_client = creds.client("cloudtrail", region_name=region)
            resp = ct_client.describe_trails()
            resources = resp.get("trailList", resp.get("Trails", []))

        elif service_name == "xray":
            xray_client = creds.client("xray", region_name=region)
            resp = xray_client.get_sampling_rules()
            resources = resp.get("SamplingRuleRecords", [])

        elif service_name == "config":
            config_client = creds.client("config", region_name=region)
            resp = config_client.describe_config_rules()
            resources = resp.get("ConfigRules", [])

        elif service_name == "sns":
            sns_client = creds.client("sns", region_name=region)
            resp = sns_client.list_topics()
            resources = resp.get("Topics", [])

        else:
            return {"error": f"Service '{service_name}' not supported."}

        return {
            "statusCode": 200,
            "statusMessage": "Success",
            "service_name": service_name,
            "resources": resources
        }

    except ClientError as e:
        return {"statusCode": 500, "statusMessage": "Error", "error": str(e)}
    except Exception as e:
        return {"statusCode": 500, "statusMessage": "Error", "error": str(e)}


# --- Generic describe endpoint ---
@router.get("/monitoring/{service_name}")
def describe_resources(
    service_name: str,
    request: Request,
    region: str = Query("us-east-1"),
    ids: Optional[List[str]] = Query(None)
):
    """Describe specific resources under a monitoring service."""
    try:
        creds = request.state.session
        service_name = service_name.lower()
        details = []

        if service_name == "cloudwatch-logs":
            logs_client = creds.client("logs", region_name=region)
            if ids:
                for log_name in ids:
                    resp = logs_client.describe_log_groups(logGroupNamePrefix=log_name)
                    details.extend(resp.get("logGroups", []))
            else:
                resp = logs_client.describe_log_groups()
                details = resp.get("logGroups", [])

        elif service_name == "cloudwatch-dashboards":
            cw_client = creds.client("cloudwatch", region_name=region)
            if ids:
                for db_name in ids:
                    resp = cw_client.get_dashboard(DashboardName=db_name)
                    details.append(resp)
            else:
                resp = cw_client.list_dashboards()
                details = resp.get("DashboardEntries", [])

        elif service_name == "cloudwatch-alarms":
            cw_client = creds.client("cloudwatch", region_name=region)
            if ids:
                resp = cw_client.describe_alarms(AlarmNames=ids)
            else:
                resp = cw_client.describe_alarms()
            details = resp.get("MetricAlarms", [])

        elif service_name == "cloudtrail":
            ct_client = creds.client("cloudtrail", region_name=region)
            if ids:
                resp = ct_client.describe_trails(trailNameList=ids)
            else:
                resp = ct_client.describe_trails()
            details = resp.get("trailList", resp.get("Trails", []))

        elif service_name == "xray":
            xray_client = creds.client("xray", region_name=region)
            resp = xray_client.get_sampling_rules()
            if ids:
                details = [r for r in resp.get("SamplingRuleRecords", []) if r["SamplingRule"]["RuleName"] in ids]
            else:
                details = resp.get("SamplingRuleRecords", [])

        elif service_name == "config":
            config_client = creds.client("config", region_name=region)
            if ids:
                resp = config_client.describe_config_rules(ConfigRuleNames=ids)
            else:
                resp = config_client.describe_config_rules()
            details = resp.get("ConfigRules", [])

        elif service_name == "sns":
            sns_client = creds.client("sns", region_name=region)
            if ids:
                for topic_arn in ids:
                    resp = sns_client.get_topic_attributes(TopicArn=topic_arn)
                    details.append(resp)
            else:
                resp = sns_client.list_topics()
                details = resp.get("Topics", [])

        else:
            return {"statusCode": 400, "statusMessage": "Invalid service"}

        return {
            "statusCode": 200,
            "statusMessage": "Success",
            "service_name": service_name,
            "details": details
        }

    except ClientError as e:
        return {"statusCode": 500, "statusMessage": "Error", "error": str(e)}
    except Exception as e:
        return {"statusCode": 500, "statusMessage": "Error", "error": str(e)}


# --- Separate endpoint for Alarms (like compute format) ---
@router.get("/monitoring/alarms/list")
def list_alarms(request: Request, region: str = Query("us-east-1")):
    try:
        creds = request.state.session
        cw_client = creds.client("cloudwatch", region_name=region)
        resp = cw_client.describe_alarms()
        return {"service_name": "cloudwatch-alarms", "resources": resp.get("MetricAlarms", [])}
    except Exception as e:
        return {"error": str(e)}


@router.get("/monitoring/alarms")
def describe_alarms(request: Request, region: str = Query("us-east-1"), ids: Optional[List[str]] = Query(None)):
    try:
        creds = request.state.session
        cw_client = creds.client("cloudwatch", region_name=region)
        if ids:
            resp = cw_client.describe_alarms(AlarmNames=ids)
        else:
            resp = cw_client.describe_alarms()
        return {"service_name": "cloudwatch-alarms", "details": resp.get("MetricAlarms", [])}
    except Exception as e:
        return {"error": str(e)}


# --- Separate endpoint for SNS (like compute format) ---
@router.get("/monitoring/sns/list")
def list_sns_topics(request: Request, region: str = Query("us-east-1")):
    try:
        creds = request.state.session
        sns_client = creds.client("sns", region_name=region)
        resp = sns_client.list_topics()
        return {"service_name": "sns", "resources": resp.get("Topics", [])}
    except Exception as e:
        return {"error": str(e)}


@router.get("/monitoring/sns")
def describe_sns_topics(request: Request, region: str = Query("us-east-1"), ids: Optional[List[str]] = Query(None)):
    try:
        creds = request.state.session
        sns_client = creds.client("sns", region_name=region)
        details = []
        if ids:
            for topic_arn in ids:
                resp = sns_client.get_topic_attributes(TopicArn=topic_arn)
                details.append(resp)
        else:
            resp = sns_client.list_topics()
            details = resp.get("Topics", [])
        return {"service_name": "sns", "details": details}
    except Exception as e:
        return {"error": str(e)}
