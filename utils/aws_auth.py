import boto3
from botocore.exceptions import ClientError
import logging

logger = logging.getLogger(__name__)

# Cache for temporary credentials
TEMP_CREDENTIALS_CACHE = {}

def assume_role(role_arn: str, session_name: str) -> dict:
    """
    Assume an AWS role and return temporary credentials.
    :param role_arn: The ARN of the role to assume.
    :param session_name: A unique session name for the assumed role.
    :return: Temporary credentials (AccessKeyId, SecretAccessKey, SessionToken).
    """
    try:
        # Check if credentials are cached
        if role_arn in TEMP_CREDENTIALS_CACHE:
            return TEMP_CREDENTIALS_CACHE[role_arn]

        sts_client = boto3.client('sts')
        response = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName=session_name
        )
        credentials = response['Credentials']

        # Cache the credentials
        TEMP_CREDENTIALS_CACHE[role_arn] = {
            "AccessKeyId": credentials['AccessKeyId'],
            "SecretAccessKey": credentials['SecretAccessKey'],
            "SessionToken": credentials['SessionToken']
        }
        return TEMP_CREDENTIALS_CACHE[role_arn]
    except ClientError as e:
        logger.error(f"Failed to assume role: {e}")
        raise e