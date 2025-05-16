from fastapi import APIRouter
import boto3
from botocore.exceptions import BotoCoreError, ClientError
from utils.response_formatter import format_response  # Import the response formatter
import json

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