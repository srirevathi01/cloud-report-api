from fastapi import APIRouter, Request, Query, HTTPException
import boto3
from botocore.exceptions import BotoCoreError, ClientError

router = APIRouter()

@router.get("/networking/{resource}/list")
def list_network_resources(
    resource: str,
    request: Request,
    account_id: str = Query(None),
    region: str = "us-east-1"
):
    try:
        creds = request.state.aws_credentials
        if resource in ["vpc", "subnet", "route-table",
                        "internet-gateway", "security-group",
                        "nacl", "elastic-ip"]:
            ec2 = boto3.client(
                "ec2",
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"],
                region_name=region
            )

            if resource == "vpc":
                return ec2.describe_vpcs()
            elif resource == "subnet":
                return ec2.describe_subnets()
            elif resource == "route-table":
                return ec2.describe_route_tables()
            elif resource == "internet-gateway":
                return ec2.describe_internet_gateways()
            elif resource == "security-group":
                return ec2.describe_security_groups()
            elif resource == "nacl":
                return ec2.describe_network_acls()
            elif resource == "elastic-ip":
                return ec2.describe_addresses()

        elif resource in ["load-balancer", "target-group"]:
            elb = boto3.client(
                "elbv2",
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"],
                region_name=region
            )
            if resource == "load-balancer":
                return elb.describe_load_balancers()
            else:
                return elb.describe_target_groups()

        else:
            raise HTTPException(400, "Supported: vpc, subnet, route-table, internet-gateway, security-group, nacl, elastic-ip, load-balancer, target-group")

    except (BotoCoreError, ClientError) as e:
        raise HTTPException(500, detail=str(e))
