from fastapi import APIRouter
import boto3
from httpx import request

router = APIRouter()

@router.get("/compute")
def list_compute_services():
    return {
        "EC2",
        "Lambda",
        "ECS"
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

# API to get detailed information about a specific EC2 instance
@router.get("/compute/ec2/{instance_id}")
def get_ec2_instance_details(instance_id: str):
    try:
        # Create a regional EC2 client
        ec2_client = boto3.client("ec2", region_name=request.query_params.get("region", "us-east-1"))
        # Retrieve instance details
        response = ec2_client.describe_instances(InstanceIds=[instance_id])

        if not response["Reservations"]:
            return {"error": "Instance not found"}

        instance = response["Reservations"][0]["Instances"][0]
        return {
            "InstanceId": instance["InstanceId"],
            "State": instance["State"]["Name"],
            "InstanceType": instance["InstanceType"],
            "LaunchTime": instance["LaunchTime"].isoformat(),
            "PublicIpAddress": instance.get("PublicIpAddress"),
            "PrivateIpAddress": instance.get("PrivateIpAddress")
        }
    except Exception as e:
        # Raise an exception to let the global middleware handle it
        raise Exception(f"Error fetching EC2 instance details: {str(e)}")


# API to list all lambda functions in a region
@router.get("/compute/lambda/all")
def list_lambda_functions(region: str = "us-east-1"):
    try:
        # Create a regional Lambda client
        lambda_client = boto3.client("lambda", region_name=region)
        # Retrieve all functions in the region
        response = lambda_client.list_functions()

        functions = []
        for function in response["Functions"]:
            functions.append({
                "FunctionName": function["FunctionName"],
                "Runtime": function["Runtime"],
                "LastModified": function["LastModified"],
                "State": function["State"]
            })

        # Return the raw data (global middleware will format it)
        return functions
    except Exception as e:
        # Raise an exception to let the global middleware handle it
        raise Exception(f"Error fetching Lambda functions: {str(e)}")

# API to get details of a specific Lambda function
@router.get("/compute/lambda/{function_name}")
def get_lambda_function_details(function_name: str, region: str = "us-east-1"):
    try:
        # Create a regional Lambda client
        lambda_client = boto3.client("lambda", region_name=region)
        # Retrieve function details
        response = lambda_client.get_function(FunctionName=function_name)

        function = response["Configuration"]
        return {
            "FunctionName": function["FunctionName"],
            "Runtime": function["Runtime"],
            "LastModified": function["LastModified"],
            "State": function["State"],
            "MemorySize": function["MemorySize"],
            "Timeout": function["Timeout"]
        }
    except Exception as e:
        # Raise an exception to let the global middleware handle it
        raise Exception(f"Error fetching Lambda function details: {str(e)}")

# API to list all ECS clusters in a region
@router.get("/compute/ecs/clusters")
def list_ecs_clusters(region: str = "us-east-1"):
    try:
        # Create a regional ECS client
        ecs_client = boto3.client("ecs", region_name=region)
        # Retrieve all clusters in the region
        response = ecs_client.list_clusters()

        clusters = []
        for cluster_arn in response["clusterArns"]:
            clusters.append({"ClusterArn": cluster_arn})

        # Return the raw data (global middleware will format it)
        return clusters
    except Exception as e:
        # Raise an exception to let the global middleware handle it
        raise Exception(f"Error fetching ECS clusters: {str(e)}")

# API to get details of a specific ECS cluster
@router.get("/compute/ecs/cluster/{cluster_name}")
def get_ecs_cluster_details(cluster_name: str, region: str = "us-east-1"):
    try:
        # Create a regional ECS client
        ecs_client = boto3.client("ecs", region_name=region)
        # Retrieve cluster details
        response = ecs_client.describe_clusters(clusters=[cluster_name])

        if not response["clusters"]:
            return {"error": "Cluster not found"}

        cluster = response["clusters"][0]
        return {
            "ClusterArn": cluster["clusterArn"],
            "Status": cluster["status"],
            "RegisteredContainerInstancesCount": cluster["registeredContainerInstancesCount"],
            "RunningTasksCount": cluster["runningTasksCount"],
            "PendingTasksCount": cluster["pendingTasksCount"]
        }
    except Exception as e:
        # Raise an exception to let the global middleware handle it
        raise Exception(f"Error fetching ECS cluster details: {str(e)}")

# API to list all ECS services in a cluster
@router.get("/compute/ecs/cluster/{cluster_name}/services")
def list_ecs_services(cluster_name: str, region: str = "us-east-1"):
    try:
        # Create a regional ECS client
        ecs_client = boto3.client("ecs", region_name=region)
        # Retrieve all services in the cluster
        response = ecs_client.list_services(cluster=cluster_name)

        services = []
        for service_arn in response["serviceArns"]:
            services.append({"ServiceArn": service_arn})

        # Return the raw data (global middleware will format it)
        return services
    except Exception as e:
        # Raise an exception to let the global middleware handle it
        raise Exception(f"Error fetching ECS services: {str(e)}")

# API tp get detailed information about a specific ECS service
@router.get("/compute/ecs/cluster/{cluster_name}/service/{service_name}")
def get_ecs_service_details(cluster_name: str, service_name: str, region: str = "us-east-1"):
    try:
        # Create a regional ECS client
        ecs_client = boto3.client("ecs", region_name=region)
        # Retrieve service details
        response = ecs_client.describe_services(cluster=cluster_name, services=[service_name])

        if not response["services"]:
            return {"error": "Service not found"}

        service = response["services"][0]
        return {
            "ServiceArn": service["serviceArn"],
            "Status": service["status"],
            "DesiredCount": service["desiredCount"],
            "RunningCount": service["runningCount"],
            "PendingCount": service["pendingCount"]
        }
    except Exception as e:
        # Raise an exception to let the global middleware handle it
        raise Exception(f"Error fetching ECS service details: {str(e)}")
