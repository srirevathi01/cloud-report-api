from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response
import logging

logger = logging.getLogger(__name__)

class DefaultRegionMiddleware(BaseHTTPMiddleware):
    """
    Middleware to set the default region to 'us-east-1' if no region is specified in the request.
    """
    async def dispatch(self, request: Request, call_next):
        query_params = request.query_params._dict.copy()
        if "region" not in query_params or not query_params["region"]:
            query_params["region"] = "us-east-1"
            logger.info("Region not specified. Defaulting to 'us-east-1'.")

        request.scope["query_string"] = "&".join(
            f"{key}={value}" for key, value in query_params.items()
        ).encode("utf-8")

        response = await call_next(request)
        return response