from fastapi import APIRouter, Request
from pydantic import BaseModel
import boto3
from botocore.exceptions import ClientError

router = APIRouter()

# --- Request body model ---
class ResourceRequest(BaseModel):
    ids: list[str]
    account_id: str | None = None
    region: str = "us-east-1"


# --- 1. GET /monitoring ---
@router.get("/monitoring")
def list_monitoring_services(request: Request):
    try:
        _ = request.state.session
        services = ["cloudwatch", "cloudtrail", "config", "xray"]
        return {"monitoring_services": services}
    except Exception as e:
        return {"error": str(e)}


# --- 2. GET /monitoring/cloudwatch/list ---
@router.get("/monitoring/cloudwatch/list")
def list_cloudwatch_resources(request: Request, region: str = "us-east-1"):
    """
    List all CloudWatch alarms and log groups in the specified region.
    """
    try:
        creds = request.state.session
        cw_client = creds.client("cloudwatch", region_name=region)
        logs_client = creds.client("logs", region_name=region)

        # Alarms
        alarms = []
        paginator = cw_client.get_paginator("describe_alarms")
        for page in paginator.paginate():
            for alarm in page.get("MetricAlarms", []):
                alarms.append(alarm["AlarmName"])

        # Log Groups
        log_groups = []
        paginator = logs_client.get_paginator("describe_log_groups")
        for page in paginator.paginate():
            for lg in page.get("logGroups", []):
                log_groups.append(lg["logGroupName"])

        return {
            "statusCode": 200,
            "statusMessage": "Success",
            "region": region,
            "cloudwatch_alarms": alarms,
            "cloudwatch_log_groups": log_groups
        }

    except ClientError as e:
        return {"statusCode": 500, "statusMessage": "AWS ClientError", "error": str(e)}
    except Exception as e:
        return {"statusCode": 500, "statusMessage": "Error", "error": str(e)}


# --- 3. POST /monitoring/cloudwatch ---
@router.post("/monitoring/cloudwatch")
def describe_cloudwatch_resources(request: Request, body: ResourceRequest):
    """
    Describe specific CloudWatch alarms or log groups.
    Will return details for alarms if name matches an alarm,
    or log groups if name matches a log group.
    """
    try:
        creds = request.state.session
        cw_client = creds.client("cloudwatch", region_name=body.region)
        logs_client = creds.client("logs", region_name=body.region)

        details = []

        for name in body.ids:
            # Try CloudWatch alarms
            alarm_resp = cw_client.describe_alarms(AlarmNames=[name])
            alarms = alarm_resp.get("MetricAlarms", [])
            if alarms:
                for alarm in alarms:
                    details.append({
                        "Type": "Alarm",
                        "Name": alarm["AlarmName"],
                        "State": alarm["StateValue"],
                        "MetricName": alarm.get("MetricName"),
                        "Namespace": alarm.get("Namespace"),
                        "Threshold": alarm.get("Threshold"),
                        "EvaluationPeriods": alarm.get("EvaluationPeriods")
                    })
                continue  # skip checking log groups if found as alarm

            # Try CloudWatch log groups
            logs_resp = logs_client.describe_log_groups(logGroupNamePrefix=name)
            log_groups = logs_resp.get("logGroups", [])
            if log_groups:
                for lg in log_groups:
                    details.append({
                        "Type": "LogGroup",
                        "Name": lg["logGroupName"],
                        "CreationTime": lg["creationTime"],
                        "StoredBytes": lg["storedBytes"]
                    })

        return {
            "statusCode": 200,
            "statusMessage": "Success",
            "account_id": body.account_id or "current",
            "region": body.region,
            "service_name": "cloudwatch",
            "details": details
        }

    except ClientError as e:
        return {"statusCode": 500, "statusMessage": "AWS ClientError", "error": str(e)}
    except Exception as e:
        return {"statusCode": 500, "statusMessage": "Error", "error": str(e)}
