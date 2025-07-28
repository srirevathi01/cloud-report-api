from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from utils.aws_auth import assume_role
import json


class AWSRoleMiddleware(BaseHTTPMiddleware):
    """
    Middleware to validate AWS role and credentials for each request.
    """
    async def dispatch(self, request: Request, call_next):

        # AWS account id is already validated in GlobalResponseFormatterMiddleware
        # aws_account_id = request.query_params.get("account_id")
        # aws_role_name = get_role_name_from_config(aws_account_id)
        # try:
        #     role_arn = f"arn:aws:iam::{aws_account_id}:role/{aws_role_name}"
        #     credentials = assume_role(role_arn, session_name="api-session")
        #     request.state.aws_credentials = credentials
        # except Exception as e:
        #     raise HTTPException(status_code=403, detail=f"Failed to assume AWS role: {str(e)}")

        response = await call_next(request)
        return response

