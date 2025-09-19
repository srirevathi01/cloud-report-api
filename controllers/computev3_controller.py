from fastapi import APIRouter, Request
from pydantic import BaseModel
import boto3
from botocore.exceptions import ClientError

router = APIRouter()


# --- Request body model for POST ---
class ResourceRequest(BaseModel):
    ids: list[str]
    region: str = "us-east-1"


# --- 1. GET /compute ---
@router.get("/computev3")
def list_compute_services(request: Request):
    """
    List all compute services supported by the API.
    """
    try:
        _ = request.state.aws_credentials  # Ensure creds are injected
        services = ["ec2", "lambda", "ecs"]
        return {"compute_services": services}
    except Exception as e:
        return {"error": str(e)}


# --- 2. GET /compute/{service_name}/list ---
@router.get("/computev3/{service_name}/list")
def list_service_resources(service_name: str, request: Request, region: str = "us-east-1"):
    """
    List all resources under a specific compute service.
    """
    try:
        creds = request.state.aws_credentials
        service_name = service_name.lower()
        resources = []

        if service_name == "ec2":
            ec2_client = boto3.client(
                "ec2",
                region_name=region,
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"]
            )
            instances = ec2_client.describe_instances()
            for reservation in instances["Reservations"]:
                for instance in reservation["Instances"]:
                    resources.append(instance["InstanceId"])

        elif service_name == "lambda":
            lambda_client = boto3.client(
                "lambda",
                region_name=region,
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"]
            )
            paginator = lambda_client.get_paginator("list_functions")
            for page in paginator.paginate():
                for fn in page.get("Functions", []):
                    resources.append(fn["FunctionName"])

        elif service_name == "ecs":
            ecs_client = boto3.client(
                "ecs",
                region_name=region,
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"]
            )
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


# --- 3. POST /compute/{service_name} ---
@router.post("/computev3/{service_name}")
def describe_resources(service_name: str, request: Request, body: ResourceRequest):
    """
    Describe specific resources under a compute service.
    Pass list of IDs in the request body.
    """
    try:
        creds = request.state.aws_credentials
        service_name = service_name.lower()
        details = []

        if service_name == "ec2":
            ec2_client = boto3.client(
                "ec2",
                region_name=body.region,
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"]
            )
            instances = ec2_client.describe_instances(InstanceIds=body.ids)
            for reservation in instances["Reservations"]:
                for instance in reservation["Instances"]:
                    details.append({
                        "InstanceId": instance["InstanceId"],
                        "State": instance["State"]["Name"],
                        "Type": instance["InstanceType"],
                        "LaunchTime": str(instance["LaunchTime"])
                    })

        elif service_name == "lambda":
            lambda_client = boto3.client(
                "lambda",
                region_name=body.region,
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"]
            )
            for fn_name in body.ids:
                fn = lambda_client.get_function(FunctionName=fn_name)
                details.append({
                    "FunctionName": fn["Configuration"]["FunctionName"],
                    "Runtime": fn["Configuration"]["Runtime"],
                    "MemorySize": fn["Configuration"]["MemorySize"],
                    "LastModified": fn["Configuration"]["LastModified"]
                })

        elif service_name == "ecs":
            ecs_client = boto3.client(
                "ecs",
                region_name=body.region,
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"]
            )

            for cluster_name in body.ids:
                # Describe cluster
                cluster_resp = ecs_client.describe_clusters(clusters=[cluster_name])
                for c in cluster_resp.get("clusters", []):
                    cluster_info = {
                        "ClusterName": c["clusterName"],
                        "Status": c["status"],
                        "RunningTasksCount": c["runningTasksCount"]
                    }

                    # List tasks in this cluster
                    tasks_resp = ecs_client.list_tasks(cluster=cluster_name)
                    tasks = []
                    if tasks_resp.get("taskArns"):
                        task_desc = ecs_client.describe_tasks(
                            cluster=cluster_name,
                            tasks=tasks_resp["taskArns"]
                        )
                        for t in task_desc.get("tasks", []):
                            tasks.append({
                                "TaskArn": t["taskArn"],
                                "LaunchType": t.get("launchType", "UNKNOWN"),
                                "LastStatus": t["lastStatus"]
                            })

                    cluster_info["Tasks"] = tasks
                    details.append(cluster_info)

        else:
            return {"error": f"Service '{service_name}' not supported."}

        return {"service_name": service_name, "details": details}

    except ClientError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": str(e)}
