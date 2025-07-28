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


        response = await call_next(request)
        return response