from fastapi import APIRouter
import boto3
from botocore.exceptions import BotoCoreError, ClientError
from utils.response_formatter import format_response  # Import the response formatter
import json
from collections import defaultdict

# Load the config file
with open("config.json", "r") as config_file:
    config = json.load(config_file)

router = APIRouter()

@router.get("/{aws_account_id}/regions")
def get_regions(aws_account_id: str):
    """
    Fetch active and inactive regions for the given AWS account ID.
    """
    try:
        print('Coming here')
        # Fetch active and inactive regions using the helper function
        regions = fetch_regions_for_account(aws_account_id)
        
        # Use the common response formatter
        return format_response(
            status_code=200,
            status_message='Successfully fetched the regions',
            data={
                "aws_account_id": aws_account_id,
                "active_regions": regions["active_regions"],
                "inactive_regions": regions["inactive_regions"]
            }
        )
    except Exception as e:
        # Use the common response formatter for errors
        return format_response(
            status_code=500,
            status_message=str(e),
            data={}
        )

def fetch_regions_for_account(aws_account_id: str):
    """
    Fetch active and inactive regions for an AWS account using an IAM STS role.
    """
    try:
        # Fetch the role name from the config file
        role_name = None
        for account in config:
            if account["account_id"] == aws_account_id:
                role_name = account["role_name"]
                break

        if not role_name:
            raise Exception(f"No role found for AWS account ID: {aws_account_id}")

        # Define the role ARN and session name
        role_arn = f"arn:aws:iam::{aws_account_id}:role/{role_name}"
        session_name = "fetchRegionsSession"

        # Assume the role
        sts_client = boto3.client("sts")
        assumed_role = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName=session_name
        )

        # Extract temporary credentials
        credentials = assumed_role["Credentials"]

        # Create an EC2 client using the assumed role credentials
        ec2_client = boto3.client(
            "ec2",
            aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"],
            aws_session_token=credentials["SessionToken"]
        )

        # Fetch all regions (active and inactive)
        regions_response = ec2_client.describe_regions(AllRegions=True)
        regions = regions_response["Regions"]

        # Separate active and inactive regions with full details
        active_regions = [
            {"RegionName": region["RegionName"], "OptInStatus": region["OptInStatus"]}
            for region in regions if region["OptInStatus"] in ["opt-in-not-required", "opted-in"]
        ]
        inactive_regions = [
            {"RegionName": region["RegionName"], "OptInStatus": region["OptInStatus"]}
            for region in regions if region["OptInStatus"] == "not-opted-in"
        ]

        return {
            "active_regions": active_regions,
            "inactive_regions": inactive_regions
        }

    except (BotoCoreError, ClientError) as e:
        raise Exception(f"Failed to fetch regions: {str(e)}")
    
# Fetch the count of services in each region for the given AWS account ID
# Output: Will return the resource count for each region
@router.get("/{aws_account_id}/resources")
def get_service_count_of_all_region(aws_account_id: str):
    """
    Fetch the count of services in each region for the given AWS account ID.
    """
    try:
        # Fetch the service count using the helper function
        service_count = fetch_service_count_by_region(aws_account_id)
        
        # Use the common response formatter
        return format_response(
            status_code=200,
            status_message='Successfully fetched the service count by region',
            data={
                "aws_account_id": aws_account_id,
                "service_count": service_count
            }
        )
    except Exception as e:
        # Use the common response formatter for errors
        return format_response(
            status_code=500,
            status_message=str(e),
            data={}
        )
    
@router.get("/{aws_account_id}/resources/{aws_region}")
def get_service_count_by_region(aws_account_id: str, aws_region:str):
    """
    Fetch the count of services in each region for the given AWS account ID.
    """
    try:
        # Fetch the service count using the helper function
        service_count = fetch_service_count_by_region(aws_account_id, aws_region)
        
        # Use the common response formatter
        return format_response(
            status_code=200,
            status_message='Successfully fetched the service count by region',
            data={
                "aws_account_id": aws_account_id,
                "service_count": service_count
            }
        )
    except Exception as e:
        # Use the common response formatter for errors
        return format_response(
            status_code=500,
            status_message=str(e),
            data={}
        )

def fetch_service_count_by_region(aws_account_id: str, resource_region=''):
    """
    Fetch active and inactive regions for an AWS account using an IAM STS role.
    """
    try:
        # Fetch the role name from the config file
        role_name = None
        for account in config:
            if account["account_id"] == aws_account_id:
                role_name = account["role_name"]
                break

        if not role_name:
            raise Exception(f"No role found for AWS account ID: {aws_account_id}")

        # Define the role ARN and session name
        role_arn = f"arn:aws:iam::{aws_account_id}:role/{role_name}"
        session_name = "fetchRegionsSession"

        # Assume the role
        sts_client = boto3.client("sts")
        assumed_role = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName=session_name
        )

        # Extract temporary credentials
        credentials = assumed_role["Credentials"]

        # Create an Resource explorer client using the assumed role credentials
        rex_client = boto3.client(
            "resource-explorer-2",
            aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"],
            aws_session_token=credentials["SessionToken"]
        )


        view_arn='arn:aws:resource-explorer-2:us-east-1:729047448122:view/all-resources/402c2bfd-ee19-4ddd-9d58-d7b47ee6a12c'
        query_string='*'
        if resource_region:
            query_string='region:{}'.format(resource_region)

        paginator = rex_client.get_paginator('search')
        region_summary = defaultdict(
            lambda: defaultdict(
                lambda: defaultdict(
                    lambda: {"count": 0, "resources": []}
                )
            )
        )

        for page in paginator.paginate(ViewArn=view_arn, QueryString=query_string, MaxResults=50):
            for resource in page.get('Resources', []):
                print(resource)
                # {'Arn': 'arn:aws:rds:ap-south-1:729047448122:pg:knackforge', 'LastReportedAt': datetime.datetime(2025, 5, 17, 12, 54, 46, tzinfo=tzutc()), 'OwningAccountId': '729047448122', 'Properties': [], 'Region': 'ap-south-1', 'ResourceType': 'rds:pg', 'Service': 'rds'}
                region = resource.get('Region', 'unknown')
                type_full = resource.get('ResourceType', 'unknown')  # e.g., "AWS::EC2::Instance"
                service = resource.get('Service', 'unknown')
                resource_name = resource.get('Arn', 'unknown')


                region_summary[region][service][type_full]['count'] += 1
                region_summary[region][service][type_full]["resources"].append(resource_name)
                # region_summary[region]['total'][type_full]['count'] += 1
        
        return region_summary

    except (BotoCoreError, ClientError) as e:
        raise Exception(f"Failed to fetch regions: {str(e)}")