from fastapi import APIRouter, Query, Request, HTTPException
from pydantic import BaseModel
from botocore.exceptions import BotoCoreError, ClientError

router = APIRouter()

# ----------------------------
# GET /logs -> List logging services
# ----------------------------
@router.get("/logs")
def list_logging_services():
    return {
        "services": [
            "cloudwatch-logs",
            "vpc-flow-logs",
            "cloudtrail-logs",
            "s3-access-logs",
            "elb-access-logs"
        ]
    }

# ----------------------------
# GET /logs/{resource} -> List logs in a region (optionally vpc-wise)
# ----------------------------
@router.get("/logs/{resource}")
def list_logging_resources(
    resource: str,
    request: Request,
    account_id: str = Query(None),
    region: str = "us-east-1",
    vpc_id: str = Query(None)
):
    session = request.state.session

    try:
        if resource == "cloudwatch-logs":
            logs = session.client("logs", region_name=region)
            log_groups = logs.describe_log_groups().get("logGroups", [])
            return {"service": resource, "log_groups": log_groups}

        elif resource == "vpc-flow-logs":
            ec2 = session.client("ec2", region_name=region)
            filters = [{"Name": "resource-id", "Values": [vpc_id]}] if vpc_id else []
            flow_logs = ec2.describe_flow_logs(Filters=filters).get("FlowLogs", [])
            return {"service": resource, "flow_logs": flow_logs}

        elif resource == "cloudtrail-logs":
            ct = session.client("cloudtrail", region_name=region)
            trails = ct.describe_trails().get("trailList", [])
            return {"service": resource, "trails": trails}

        elif resource == "s3-access-logs":
            s3 = session.client("s3", region_name=region)
            buckets = s3.list_buckets().get("Buckets", [])
            owner = s3.list_buckets().get("Owner", {})
            bucket_logs = []
            for b in buckets:
                try:
                    logging_info = s3.get_bucket_logging(Bucket=b["Name"])
                    versioning = s3.get_bucket_versioning(Bucket=b["Name"]).get("Status", "None")
                    bucket_region = s3.get_bucket_location(Bucket=b["Name"]).get("LocationConstraint") or "us-east-1"
                    bucket_logs.append({
                        "BucketName": b["Name"],
                        "TargetBucket": logging_info.get("LoggingEnabled", {}).get("TargetBucket"),
                        "TargetPrefix": logging_info.get("LoggingEnabled", {}).get("TargetPrefix"),
                        "Versioning": versioning,
                        "Region": bucket_region,
                        "Owner": {
                            "DisplayName": owner.get("DisplayName"),
                            "ID": owner.get("ID")
                        }
                    })
                except Exception:
                    continue
            return {"service": resource, "bucket_logs": bucket_logs}

        elif resource == "elb-access-logs":
            elb = session.client("elb", region_name=region)
            lbs = elb.describe_load_balancers().get("LoadBalancerDescriptions", [])
            lb_logs = []
            for lb in lbs:
                lb_logs.append({
                    "LoadBalancerName": lb["LoadBalancerName"],
                    "Scheme": lb["Scheme"],
                    "DNSName": lb["DNSName"],
                    "AccessLog": lb.get("AccessLog", {})
                })
            return {"service": resource, "elb_logs": lb_logs}

        else:
            raise HTTPException(
                status_code=400,
                detail="Supported services: cloudwatch-logs, vpc-flow-logs, cloudtrail-logs, s3-access-logs, elb-access-logs"
            )

    except (BotoCoreError, ClientError) as e:
        raise HTTPException(status_code=500, detail=str(e))


# ----------------------------
# POST /logging/{resource} -> Describe specific logs
# ----------------------------
class ResourceIds(BaseModel):
    ids: list[str]

@router.post("/logs/{resource}")
def describe_specific_logging_resource(
    resource: str,
    resource_ids: ResourceIds,
    request: Request,
    region: str = "us-east-1"
):
    session = request.state.session
    simplified = []

    try:
        if resource == "cloudwatch-logs":
            logs = session.client("logs", region_name=region)
            for lg_name in resource_ids.ids:
                try:
                    lg = logs.describe_log_groups(logGroupNamePrefix=lg_name)["logGroups"]
                    simplified.extend(lg)
                except Exception:
                    continue

        elif resource == "vpc-flow-logs":
            ec2 = session.client("ec2", region_name=region)
            flow_logs = ec2.describe_flow_logs(Filters=[{"Name": "resource-id", "Values": resource_ids.ids}]).get("FlowLogs", [])
            simplified.extend(flow_logs)

        elif resource == "cloudtrail-logs":
            ct = session.client("cloudtrail", region_name=region)
            trails = ct.describe_trails()["trailList"]
            for t in trails:
                if t["Name"] in resource_ids.ids:
                    simplified.append(t)

        elif resource == "s3-access-logs":
            s3 = session.client("s3", region_name=region)
            owner = s3.list_buckets().get("Owner", {})
            for b_name in resource_ids.ids:
                try:
                    logging_info = s3.get_bucket_logging(Bucket=b_name).get("LoggingEnabled", {})
                    versioning = s3.get_bucket_versioning(Bucket=b_name).get("Status", "None")
                    bucket_region = s3.get_bucket_location(Bucket=b_name).get("LocationConstraint") or "us-east-1"
                    if logging_info:
                        simplified.append({
                            "BucketName": b_name,
                            "TargetBucket": logging_info.get("TargetBucket"),
                            "TargetPrefix": logging_info.get("TargetPrefix"),
                            "Versioning": versioning,
                            "Region": bucket_region,
                            "Owner": {
                                "DisplayName": owner.get("DisplayName"),
                                "ID": owner.get("ID")
                            }
                        })
                except Exception:
                    continue

        elif resource == "elb-access-logs":
            elb = session.client("elb", region_name=region)
            lbs = elb.describe_load_balancers()["LoadBalancerDescriptions"]
            for lb in lbs:
                if lb["LoadBalancerName"] in resource_ids.ids:
                    simplified.append({
                        "LoadBalancerName": lb["LoadBalancerName"],
                        "Scheme": lb["Scheme"],
                        "DNSName": lb["DNSName"],
                        "AccessLog": lb.get("AccessLog", {})
                    })

        else:
            raise HTTPException(
                status_code=400,
                detail="Supported services: cloudwatch-logs, vpc-flow-logs, cloudtrail-logs, s3-access-logs, elb-access-logs"
            )

        return {"service": resource, "resources": simplified}

    except (BotoCoreError, ClientError) as e:
        raise HTTPException(status_code=500, detail=str(e))
    