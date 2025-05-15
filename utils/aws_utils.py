import boto3
from boto3.session import Session
from fastapi import HTTPException
import logging

logger = logging.getLogger(__name__)

_aws_clients = {}

def get_aws_client(service_name: str, region: str = None):
    """Get or create an AWS client with optional region."""
    if region:
        return boto3.client(service_name, region_name=region)
    if service_name not in _aws_clients:
        _aws_clients[service_name] = boto3.client(service_name)
    return _aws_clients[service_name]

def get_all_regions(service_name: str) -> list[str]:
    """Retrieve all active/enabled regions for a given AWS service."""
    ec2_client = boto3.client('ec2')
    try:
        response = ec2_client.describe_regions(AllRegions=False)
        active_regions = [region['RegionName'] for region in response['Regions']]
        session = Session()
        available_regions = session.get_available_regions(service_name)
        return [region for region in active_regions if region in available_regions]
    except Exception as e:
        logger.error(f"Error retrieving active regions: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve active regions")