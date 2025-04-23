from fastapi import APIRouter
import boto3
from botocore.exceptions import BotoCoreError, ClientError
from utils.response_formatter import format_response  # Import the response formatter

router = APIRouter()

@router.get("/{aws_account_id}/regions")
def get_active_regions(aws_account_id: str):
    """
    Fetch active regions for the given AWS account ID.
    """
    try:
        # Fetch active regions using the helper function
        active_regions = fetch_active_regions_for_account(aws_account_id)
        
        # Use the common response formatter
        return format_response(
            status_code=200,
            status_message='Successfully fetched the regions',
            data={
                "aws_account_id": aws_account_id,
                "active_regions": active_regions
            }
        )
    except Exception as e:
        # Use the common response formatter for errors
        return format_response(
            status_code=500,
            status_message=str(e),
            data={}
        )

def fetch_active_regions_for_account(aws_account_id: str):
    """
    Fetch active regions for an AWS account using an IAM STS role.
    """
    try:
        # Define the role ARN and session name
        role_arn = f"arn:aws:iam::{aws_account_id}:role/YourRoleName"
        session_name = "fetchActiveRegionsSession"

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

        # Fetch all available regions
        regions_response = ec2_client.describe_regions()
        regions = [region["RegionName"] for region in regions_response["Regions"]]

        return regions

    except (BotoCoreError, ClientError) as e:
        raise Exception(f"Failed to fetch regions: {str(e)}")