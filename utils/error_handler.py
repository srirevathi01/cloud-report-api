from fastapi import HTTPException
from botocore.exceptions import ClientError
import logging

logger = logging.getLogger(__name__)

def handle_aws_client_error(e: ClientError):
    """Handle AWS ClientError exceptions."""
    error_code = e.response['Error']['Code']
    if error_code == 'DBInstanceNotFound':
        raise HTTPException(status_code=404, detail="Instance not found")
    logger.error(f"AWS Client Error: {e}")
    raise HTTPException(status_code=400, detail=str(e))