from fastapi import APIRouter, Request
from pydantic import BaseModel
import boto3
from botocore.exceptions import ClientError

router = APIRouter()

# --- Request body model for POST ---
class ResourceRequest(BaseModel):
    ids: list[str]
    region: str = "us-east-1"


# --- 1. GET /monitoring ---
@router.get("/monitoring")
def list_monitoring_services(request: Request):
    """
    List all monitoring services supported by the API.
    """
    try:
        _ = request.state.session  # Ensure creds are injected
        services = ["cloudwatch", "xray", "cloudtrail", "config"]
        return {"monitoring_services": services}
    except Exception as e:
        return {"error": str(e)}


# --- 2. GET /monitoring/{service_name}/list ---
@router.get("/monitoring/{service_name}/list")
def list_service_resources(service_name: str, request: Request, region: str = "us-east-1"):
    """
    List all resources under a specific monitoring service.
    """
    try:
        creds = request.state.session
        service_name = service_name.lower()
        resources = []

        if service_name == "cloudwatch":
            cw_client = creds.client("cloudwatch", region_name=region)
            paginator = cw_client.get_paginator("describe_alarms")
            for page in paginator.paginate():
                for alarm in page.get("MetricAlarms", []):
                    resources.append(alarm["AlarmName"])

        elif service_name == "xray":
            xray_client = creds.client("xray", region_name=region)
            resp = xray_client.get_sampling_rules()
            for rule in resp.get("SamplingRuleRecords", []):
                resources.append(rule["SamplingRule"]["RuleName"])

        elif service_name == "cloudtrail":
            ct_client = creds.client("cloudtrail", region_name=region)
            resp = ct_client.describe_trails()
            for trail in resp.get("trailList", []):
                resources.append(trail["Name"])

        elif service_name == "config":
            config_client = creds.client("config", region_name=region)
            resp = config_client.list_discovered_resources()
            for res in resp.get("resourceIdentifiers", []):
                resources.append(res.get("resourceId", "UNKNOWN"))

        else:
            return {"error": f"Service '{service_name}' not supported."}

        return {"service_name": service_name, "resources": resources}

    except ClientError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": str(e)}


# --- 3. POST /monitoring/{service_name} ---
@router.post("/monitoring/{service_name}")
def describe_resources(service_name: str, request: Request, body: ResourceRequest):
    """
    Describe specific resources under a monitoring service.
    Pass list of IDs in the request body.
    """
    try:
        creds = request.state.session
        service_name = service_name.lower()
        details = []

        if service_name == "cloudwatch":
            cw_client = creds.client("cloudwatch", region_name=body.region)
            for alarm_name in body.ids:
                resp = cw_client.describe_alarms(AlarmNames=[alarm_name])
                for alarm in resp.get("MetricAlarms", []):
                    details.append({
                        "AlarmName": alarm["AlarmName"],
                        "MetricName": alarm.get("MetricName"),
                        "Namespace": alarm.get("Namespace"),
                        "StateValue": alarm["StateValue"],
                        "Threshold": alarm["Threshold"],
                        "ComparisonOperator": alarm["ComparisonOperator"]
                    })

        elif service_name == "xray":
            xray_client = creds.client("xray", region_name=body.region)
            for trace_id in body.ids:
                resp = xray_client.batch_get_traces(TraceIds=[trace_id])
                for trace in resp.get("Traces", []):
                    details.append({
                        "Id": trace["Id"],
                        "Duration": trace.get("Duration"),
                        "Segments": len(trace.get("Segments", []))
                    })

        elif service_name == "cloudtrail":
            ct_client = creds.client("cloudtrail", region_name=body.region)
            for trail_name in body.ids:
                resp = ct_client.get_trail(Name=trail_name)
                details.append({
                    "Name": resp["Trail"]["Name"],
                    "HomeRegion": resp["Trail"]["HomeRegion"],
                    "IsMultiRegionTrail": resp["Trail"]["IsMultiRegionTrail"],
                    "LogFileValidationEnabled": resp["Trail"]["LogFileValidationEnabled"],
                })

        elif service_name == "config":
            config_client = creds.client("config", region_name=body.region)
            for resource_id in body.ids:
                resp = config_client.get_resource_config_history(
                    resourceType='AWS::AllSupported',  # Or specific type if known
                    resourceId=resource_id,
                    limit=1
                )
                if resp.get("configurationItems"):
                    item = resp["configurationItems"][0]
                    details.append({
                        "ResourceId": item["resourceId"],
                        "ResourceType": item["resourceType"],
                        "ConfigurationStateId": item["configurationStateId"],
                        "Configuration": item.get("configuration"),
                        "ComplianceStatus": item.get("configurationItemStatus")
                    })

        else:
            return {"error": f"Service '{service_name}' not supported."}

        return {"service_name": service_name, "details": details}

    except ClientError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": str(e)}
