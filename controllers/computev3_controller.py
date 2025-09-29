from fastapi import APIRouter, Request
from pydantic import BaseModel
import boto3
from botocore.exceptions import ClientError

router = APIRouter()

# --- Request body model for POST ---
class ResourceRequest(BaseModel):
    ids: list[str]
    region: str = "us-east-1"

# --- 1. GET /computev3 ---
@router.get("/computev3")
def list_compute_services(request: Request):
    """List all compute services supported by the API."""
    try:
        _ = request.state.session  # Ensure creds are injected
        services = ["ec2", "lambda", "ecs"]
        return {"compute_services": services}
    except Exception as e:
        return {"error": str(e)}

# --- 2. GET /computev3/{service_name}/list ---
@router.get("/computev3/{service_name}/list")
def list_service_resources(service_name: str, request: Request, region: str = "us-east-1"):
    """List all resources under a specific compute service."""
    try:
        creds = request.state.session
        service_name = service_name.lower()
        resources = []

        if service_name == "ec2":
            ec2_client = creds.client("ec2", region_name=region)
            instances = ec2_client.describe_instances()
            for reservation in instances["Reservations"]:
                for instance in reservation["Instances"]:
                    resources.append({
                        "InstanceId": instance["InstanceId"],
                        "State": instance["State"]["Name"],
                        "Type": instance["InstanceType"],
                        "Family": instance["InstanceType"].split('.')[0],
                        "LaunchTime": str(instance["LaunchTime"])
                    })

        elif service_name == "lambda":
            lambda_client = creds.client("lambda", region_name=region)
            paginator = lambda_client.get_paginator("list_functions")
            for page in paginator.paginate():
                for fn in page.get("Functions", []):
                    resources.append({
                        "FunctionName": fn["FunctionName"],
                        "Runtime": fn.get("Runtime"),
                        "MemorySize": fn.get("MemorySize"),
                        "Timeout": fn.get("Timeout"),
                        "LastModified": fn.get("LastModified"),
                        "State": fn.get("State", "Unknown")
                    })

        elif service_name == "ecs":
            ecs_client = creds.client("ecs", region_name=region)
            clusters = ecs_client.list_clusters()
            for arn in clusters.get("clusterArns", []):
                cluster_name = arn.split("/")[-1]
                resources.append(cluster_name)

        else:
            return {"error": f"Service '{service_name}' not supported."}

        return {"service_name": service_name, "resources": resources}

    except ClientError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": str(e)}

# --- 3. POST /computev3/{service_name} ---
@router.post("/computev3/{service_name}")
def describe_resources(service_name: str, request: Request, body: ResourceRequest):
    """Describe specific resources under a compute service (EC2, Lambda, ECS)."""
    try:
        creds = request.state.session
        service_name = service_name.lower()
        details = []

        if service_name == "ec2":
            ec2_client = creds.client("ec2", region_name=body.region)
            instances = ec2_client.describe_instances(InstanceIds=body.ids)
            for reservation in instances["Reservations"]:
                for instance in reservation["Instances"]:
                    details.append({
                        "InstanceId": instance["InstanceId"],
                        "State": instance["State"]["Name"],
                        "Type": instance["InstanceType"],
                        "Family": instance["InstanceType"].split('.')[0],
                        "LaunchTime": str(instance["LaunchTime"])
                    })

        elif service_name == "lambda":
            lambda_client = creds.client("lambda", region_name=body.region)
            for fn_name in body.ids:
                fn = lambda_client.get_function(FunctionName=fn_name)
                config = fn.get("Configuration", {})
                details.append({
                    "FunctionName": config.get("FunctionName"),
                    "Runtime": config.get("Runtime"),
                    "MemorySize": config.get("MemorySize"),
                    "Timeout": config.get("Timeout"),
                    "LastModified": config.get("LastModified"),
                    "State": config.get("State", "Unknown")
                })

        elif service_name == "ecs":
            ecs_client = creds.client("ecs", region_name=body.region)

            for cluster_name in body.ids:
                cluster_resp = ecs_client.describe_clusters(clusters=[cluster_name])
                for c in cluster_resp.get("clusters", []):
                    cluster_info = {
                        "ClusterName": c["clusterName"],
                        "Status": c["status"],
                        "RunningTasksCount": c["runningTasksCount"],
                        "ActiveServicesCount": c["activeServicesCount"],
                        "Services": []
                    }

                    # --- Services in this Cluster ---
                    services_resp = ecs_client.list_services(cluster=cluster_name)
                    service_arns = services_resp.get("serviceArns", [])
                    if service_arns:
                        service_desc = ecs_client.describe_services(
                            cluster=cluster_name,
                            services=service_arns
                        )
                        for s in service_desc.get("services", []):
                            service_info = {
                                "ServiceName": s["serviceName"],
                                "Status": s["status"],
                                "DesiredCount": s["desiredCount"],
                                "RunningCount": s["runningCount"],
                                "Tasks": []
                            }

                            # --- Tasks in this Service ---
                            tasks_resp = ecs_client.list_tasks(cluster=cluster_name, serviceName=s["serviceName"])
                            if tasks_resp.get("taskArns"):
                                task_desc = ecs_client.describe_tasks(
                                    cluster=cluster_name,
                                    tasks=tasks_resp["taskArns"]
                                )
                                for t in task_desc.get("tasks", []):
                                    service_info["Tasks"].append({
                                        "TaskArn": t["taskArn"],
                                        "LaunchType": t.get("launchType", "UNKNOWN"),
                                        "LastStatus": t["lastStatus"],
                                        "DesiredStatus": t["desiredStatus"]
                                    })

                                # Set service launch type based on first task (if exists)
                                if service_info["Tasks"]:
                                    service_info["LaunchType"] = service_info["Tasks"][0]["LaunchType"]
                                else:
                                    service_info["LaunchType"] = "UNKNOWN"

                            cluster_info["Services"].append(service_info)

                    details.append(cluster_info)

        else:
            return {"error": f"Service '{service_name}' not supported."}

        return {"service_name": service_name, "details": details}

    except ClientError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": str(e)}
