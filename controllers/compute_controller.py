from fastapi import APIRouter
import boto3
from httpx import request

router = APIRouter()

@router.get("/compute")
def list_compute_services():
    return {
        "EC2",
        "Lambda",
        "ECS",
        "EKS",
        "Lightsail",
        "Batch",
        "Outposts"
    }

@router.get("/compute/ec2/all")
def list_ec2_instances(region: str = "us-east-1"):
    try:
        response = {"Reservations": []}
        # Create a regional EC2 client
        ec2_client = boto3.client("ec2", region_name=region)
        # Retrieve instances in the region
        regional_response = ec2_client.describe_instances()
        response["Reservations"].extend(regional_response["Reservations"])

        instances = []
        for reservation in response["Reservations"]:
            for instance in reservation["Instances"]:
                instances.append({
                    "InstanceId": instance["InstanceId"],
                    "State": instance["State"]["Name"],
                    "InstanceType": instance["InstanceType"],
                    "LaunchTime": instance["LaunchTime"].isoformat()
                })

        # Return the raw data (global middleware will format it)
        return instances
    except Exception as e:
        # Raise an exception to let the global middleware handle it
        raise Exception(f"Error fetching EC2 instances: {str(e)}")