import boto3
from botocore.exceptions import ClientError
from datetime import datetime, timezone, timedelta
import logging

logger = logging.getLogger(__name__)

# Cache for temporary credentials with expiration tracking
TEMP_CREDENTIALS_CACHE = {}

def assume_role(role_arn: str, session_name: str) -> dict:
    """
    Assume an AWS role and return temporary credentials.
    Uses ECS task role to assume the target role.
    Caches credentials and refreshes them before expiration.

    :param role_arn: The ARN of the role to assume.
    :param session_name: A unique session name for the assumed role.
    :return: Boto3 session with temporary credentials.
    """
    try:
        # Check if credentials are cached and still valid (with 5-minute buffer)
        if role_arn in TEMP_CREDENTIALS_CACHE:
            cached = TEMP_CREDENTIALS_CACHE[role_arn]
            expiration = cached["Expiration"]

            # Refresh if credentials expire in less than 5 minutes
            buffer_time = datetime.now(timezone.utc) + timedelta(minutes=5)

            if expiration > buffer_time:
                logger.info(f"Using cached credentials for {role_arn} (expires at {expiration})")
                session = boto3.Session(
                    aws_access_key_id=cached["AccessKeyId"],
                    aws_secret_access_key=cached["SecretAccessKey"],
                    aws_session_token=cached["SessionToken"],
                )
                return session
            else:
                logger.info(f"Cached credentials for {role_arn} expired or expiring soon, refreshing...")

        # Create STS client using ECS task role (default credentials from environment)
        # This will automatically use the IAM role attached to the ECS task
        sts_client = boto3.client('sts')

        logger.info(f"Assuming role: {role_arn}")
        response = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName=session_name,
            DurationSeconds=3600  # 1 hour (can be adjusted between 900-43200 seconds)
        )
        credentials = response['Credentials']

        # Cache the credentials with expiration time
        TEMP_CREDENTIALS_CACHE[role_arn] = {
            "AccessKeyId": credentials['AccessKeyId'],
            "SecretAccessKey": credentials['SecretAccessKey'],
            "SessionToken": credentials['SessionToken'],
            "Expiration": credentials['Expiration']
        }

        logger.info(f"Successfully assumed role {role_arn} (expires at {credentials['Expiration']})")

        session = boto3.Session(
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken'],
        )
        return session
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', 'Unknown')
        error_message = e.response.get('Error', {}).get('Message', str(e))
        logger.error(f"Failed to assume role {role_arn}: {error_code} - {error_message}")
        raise e