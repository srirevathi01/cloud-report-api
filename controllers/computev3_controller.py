from fastapi import APIRouter, Request
import boto3
from botocore.exceptions import ClientError

router = APIRouter()

# GET /compute
@router.get("/computev3")
def list_compute_services(request: Request):
    """
    List all compute services used in the AWS account.
    """
    try:
        # AWS credentials are provided by middleware
        creds = request.state.aws_credentials

        # Services we care about
        services = ["ec2", "lambda", "ecs"]

        #  return plain dict, middleware will format
        return {"compute_services": services}

    except Exception as e:
        return {"error": str(e)}


# GET /compute/{service_name}/list
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
                    resources.append(f"InstanceId: {instance['InstanceId']}")

        elif service_name == "lambda":
            lambda_client = boto3.client(
                "lambda",
                region_name=region,
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"]
            )
            functions = lambda_client.list_functions()
            for fn in functions.get("Functions", []):
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
                resources.append(f"Cluster: {arn.split('/')[-1]}")

        else:
            return {"error": f"Service '{service_name}' not supported."}

        # return plain dict, middleware will format
        return {"service_name": service_name, "resources": resources}

    except ClientError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": str(e)}
