from fastapi import APIRouter, Request
from pydantic import BaseModel, Field
import boto3
from botocore.exceptions import BotoCoreError, ClientError
from utils.response_formatter import format_response  # Import the response formatter
import json

from collections import defaultdict

# Load the config file with error handling and absolute path
import os
config_path = os.path.join(os.path.dirname(__file__), '..', 'config.json')

try:
    with open(config_path, "r") as config_file:
        config = json.load(config_file)
except Exception as e:
    print(f"Error loading config.json from {config_path}: {e}")
    config = []

router = APIRouter()

@router.get(
    "/{aws_account_id}/regions",
    summary="Fetch active and inactive regions for the given AWS account ID"
)
def get_regions(aws_account_id: str, request: Request):
    """
    Fetch active and inactive regions for the given AWS account ID.
    """
    try:
        # Fetch active and inactive regions using the helper function
        regions = fetch_regions_for_account(aws_account_id, request.state.aws_credentials)
        
        # Use the common response formatter
        return {
                "aws_account_id": aws_account_id,
                "active_regions": regions["active_regions"],
                "inactive_regions": regions["inactive_regions"]
            }
    except Exception as e:
        import traceback
        tb_str = traceback.format_exc()
        # Use the common response formatter for errors, including stacktrace
        return format_response(
            status_code=500,
            status_message=str(e),
            data={"traceback": tb_str}
        )
    
# Fetch the count of services in each region for the given AWS account ID
# Output: Will return the resource count for each region
@router.get(
    "/{aws_account_id}/resources",
    summary="Fetch the count of services in each region for the given AWS account ID"
)
def get_service_count_of_all_region(aws_account_id: str):
    """
    Fetch the count of services in each region for the given AWS account ID.
    """
    try:
        # Fetch the service count using the helper function
        service_count = fetch_service_count_by_region(aws_account_id)
        
        # Use the common response formatter
        return {
                "aws_account_id": aws_account_id,
                "service_count": service_count
        }
    except Exception as e:
        # Use the common response formatter for errors
        raise Exception(f"Failed to get resource count in region: {str(e)}")
    
@router.get(
    "/{aws_account_id}/resources/{aws_region}",
    summary="Fetch the count of services in a specific region for the given AWS account ID"
)
def get_service_count_by_region(aws_account_id: str, aws_region: str):
    """
    Fetch the count of services in each region for the given AWS account ID.
    """
    try:
        # Fetch the service count using the helper function
        service_count = fetch_service_count_by_region(aws_account_id, aws_region)
        
        # Use the common response formatter
        return {
                "aws_account_id": aws_account_id,
                "service_count": service_count
        }
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
        

        resource_explorer_view_arn = None
        for account in config:
            if account["account_id"] == aws_account_id:
                resource_explorer_view_arn = account["resource_explorer_view_arn"]
                break

        if not resource_explorer_view_arn:
            raise Exception(f"Create resource explorer view for AWS account ID: {aws_account_id}")

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
            region_name='us-east-1',
            aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"],
            aws_session_token=credentials["SessionToken"]
        )

        # Fetch the resources using the Resource Explorer client
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

        region = rex_client.meta.region_name
        for page in paginator.paginate(ViewArn=resource_explorer_view_arn, QueryString=query_string, MaxResults=50):
            for resource in page.get('Resources', []):
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
    
def fetch_regions_for_account(aws_account_id: str, credentials):
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
        

        resource_explorer_view_arn = None
        for account in config:
            if account["account_id"] == aws_account_id:
                resource_explorer_view_arn = account["resource_explorer_view_arn"]
                break

        if not resource_explorer_view_arn:
            raise Exception(f"Create resource explorer view for AWS account ID: {aws_account_id}")

        print(f"Assumed role credentials: {credentials}")
        # Create an EC2 client using the assumed role credentials
        ec2_client = boto3.client(
            "ec2",
            region_name='us-east-1',
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
