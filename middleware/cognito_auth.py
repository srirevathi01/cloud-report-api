"""
Cognito JWT Token Validation Middleware for FastAPI

This middleware validates JWT tokens from AWS Cognito and extracts user information.
"""

import os
import time
import logging
from typing import Optional, Dict, Any
from functools import lru_cache

import httpx
from jose import jwt, JWTError
from fastapi import Request, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger(__name__)

# Security scheme for Swagger docs
security = HTTPBearer()


class CognitoConfig:
    """Cognito configuration from environment variables"""

    def __init__(self):
        self.region = os.getenv('COGNITO_REGION', 'us-east-1')
        self.user_pool_id = os.getenv('COGNITO_USER_POOL_ID', '')
        self.client_id = os.getenv('COGNITO_CLIENT_ID', '')
        self.jwks_url = f"https://cognito-idp.{self.region}.amazonaws.com/{self.user_pool_id}/.well-known/jwks.json"
        self.issuer = f"https://cognito-idp.{self.region}.amazonaws.com/{self.user_pool_id}"

    def is_configured(self) -> bool:
        """Check if Cognito is properly configured"""
        return bool(self.user_pool_id and self.client_id)


cognito_config = CognitoConfig()


@lru_cache(maxsize=1)
def get_jwks() -> Dict[str, Any]:
    """
    Fetch and cache JWKS (JSON Web Key Set) from Cognito
    """
    try:
        response = httpx.get(cognito_config.jwks_url, timeout=10.0)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        logger.error(f"Failed to fetch JWKS: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Unable to fetch authentication keys"
        )


def get_signing_key(token: str) -> Optional[Dict[str, Any]]:
    """
    Get the signing key for a JWT token from JWKS
    """
    try:
        # Get the key ID from the token header
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header.get('kid')

        if not kid:
            logger.error("Token missing 'kid' in header")
            return None

        # Get JWKS
        jwks = get_jwks()

        # Find the matching key
        for key in jwks.get('keys', []):
            if key.get('kid') == kid:
                return key

        logger.error(f"No matching key found for kid: {kid}")
        return None

    except Exception as e:
        logger.error(f"Error getting signing key: {e}")
        return None


def verify_token(token: str) -> Dict[str, Any]:
    """
    Verify and decode a Cognito JWT token

    Args:
        token: The JWT token to verify

    Returns:
        The decoded token payload

    Raises:
        HTTPException: If token verification fails
    """
    try:
        # Get the signing key
        signing_key = get_signing_key(token)
        if not signing_key:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token: Unable to find signing key",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Verify and decode the token
        payload = jwt.decode(
            token,
            signing_key,
            algorithms=['RS256'],
            audience=cognito_config.client_id,
            issuer=cognito_config.issuer,
            options={
                'verify_signature': True,
                'verify_aud': True,
                'verify_iat': True,
                'verify_exp': True,
                'verify_nbf': False,
                'verify_iss': True,
                'verify_sub': True,
                'verify_jti': False,
                'verify_at_hash': False,
                'require_aud': True,
                'require_iat': True,
                'require_exp': True,
                'require_nbf': False,
                'require_iss': True,
                'require_sub': True,
                'require_jti': False,
                'require_at_hash': False,
            }
        )

        # Additional validation
        current_time = time.time()

        if payload.get('exp', 0) < current_time:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has expired",
                headers={"WWW-Authenticate": "Bearer"},
            )

        if payload.get('token_use') != 'id':
            logger.warning(f"Invalid token use: {payload.get('token_use')}")

        return payload

    except JWTError as e:
        logger.error(f"JWT verification failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error verifying token: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token verification failed",
            headers={"WWW-Authenticate": "Bearer"},
        )


def extract_user_info(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract user information from token payload

    Args:
        payload: The decoded JWT payload

    Returns:
        Dictionary containing user information
    """
    return {
        'sub': payload.get('sub'),
        'username': payload.get('cognito:username', payload.get('sub')),
        'email': payload.get('email'),
        'email_verified': payload.get('email_verified', False),
        'groups': payload.get('cognito:groups', []),
        'token_use': payload.get('token_use'),
        'auth_time': payload.get('auth_time'),
        'exp': payload.get('exp'),
    }


class CognitoAuthMiddleware(BaseHTTPMiddleware):
    """
    Middleware to validate Cognito JWT tokens on all requests
    """

    def __init__(self, app, exclude_paths: list = None):
        super().__init__(app)
        self.exclude_paths = exclude_paths or ['/docs', '/redoc', '/openapi.json', '/health']

    async def dispatch(self, request: Request, call_next):
        # Skip authentication for OPTIONS requests (CORS preflight)
        if request.method == "OPTIONS":
            return await call_next(request)

        # Skip authentication for excluded paths
        if any(request.url.path.startswith(path) for path in self.exclude_paths):
            return await call_next(request)

        # Skip if Cognito is not configured (for development)
        if not cognito_config.is_configured():
            logger.warning("Cognito not configured - skipping authentication")
            request.state.user = None
            return await call_next(request)

        # Extract token from Authorization header
        auth_header = request.headers.get('Authorization')

        if not auth_header:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing Authorization header",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Parse Bearer token
        parts = auth_header.split()
        if len(parts) != 2 or parts[0].lower() != 'bearer':
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid Authorization header format. Expected 'Bearer <token>'",
                headers={"WWW-Authenticate": "Bearer"},
            )

        token = parts[1]

        # Verify token
        try:
            payload = verify_token(token)
            user_info = extract_user_info(payload)

            # Attach user info to request state
            request.state.user = user_info

            logger.info(f"Authenticated user: {user_info.get('username')} with groups: {user_info.get('groups')}")

        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Authentication failed: {e}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication failed",
                headers={"WWW-Authenticate": "Bearer"},
            )

        response = await call_next(request)
        return response


def get_current_user(request: Request) -> Optional[Dict[str, Any]]:
    """
    Dependency to get current authenticated user from request state

    Usage in route:
        @app.get("/api/endpoint")
        async def endpoint(request: Request):
            user = get_current_user(request)
            if user:
                print(f"User: {user['username']}")
    """
    return getattr(request.state, 'user', None)


def require_auth(request: Request) -> Dict[str, Any]:
    """
    Dependency that requires authentication

    Usage in route:
        from fastapi import Depends

        @app.get("/api/endpoint")
        async def endpoint(user: dict = Depends(require_auth)):
            print(f"Authenticated user: {user['username']}")
    """
    user = get_current_user(request)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


def require_group(required_groups: list):
    """
    Dependency factory that requires user to be in specific Cognito groups

    Usage in route:
        from fastapi import Depends

        @app.get("/api/admin")
        async def admin_endpoint(user: dict = Depends(require_group(['Admins']))):
            print(f"Admin user: {user['username']}")
    """
    def check_group(request: Request) -> Dict[str, Any]:
        user = require_auth(request)
        user_groups = user.get('groups', [])

        if not any(group in user_groups for group in required_groups):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"User must be in one of these groups: {required_groups}"
            )

        return user

    return check_group
