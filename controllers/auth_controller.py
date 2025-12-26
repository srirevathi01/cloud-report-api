"""
Authentication controller for handling Cognito token exchange via backend proxy.

This allows using a confidential client (with client secret) securely
by keeping the secret on the backend instead of exposing it in the browser.
"""

import os
import base64
import logging
from typing import Dict, Any

import httpx
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

logger = logging.getLogger(__name__)

router = APIRouter()


def get_cognito_config() -> tuple[str, str, str]:
    """
    Get Cognito configuration from environment variables.

    Returns:
        Tuple of (domain, client_id, client_secret)

    Raises:
        HTTPException: If configuration is incomplete
    """
    cognito_domain = os.getenv('COGNITO_DOMAIN', '')
    client_id = os.getenv('COGNITO_CLIENT_ID', '')
    client_secret = os.getenv('COGNITO_CLIENT_SECRET', '')

    if not all([cognito_domain, client_id, client_secret]):
        raise HTTPException(
            status_code=500,
            detail="Cognito configuration incomplete"
        )

    return cognito_domain, client_id, client_secret


class TokenExchangeRequest(BaseModel):
    """Request model for token exchange"""
    code: str
    code_verifier: str
    redirect_uri: str


class TokenExchangeResponse(BaseModel):
    """Response model for token exchange"""
    id_token: str
    access_token: str
    refresh_token: str
    expires_in: int
    token_type: str


class RefreshTokenRequest(BaseModel):
    """Request model for token refresh"""
    refresh_token: str


@router.post("/auth/token-exchange", response_model=TokenExchangeResponse)
async def exchange_token(request: TokenExchangeRequest):
    """
    Exchange authorization code for tokens using backend proxy.

    Securely handles token exchange with Cognito using client secret
    stored on backend (not exposed to frontend).
    """
    try:
        # Get Cognito configuration
        cognito_domain, client_id, client_secret = get_cognito_config()

        # Prepare token endpoint URL
        token_url = f"https://{cognito_domain}/oauth2/token"

        # Create Basic Auth header with client_id:client_secret
        credentials = f"{client_id}:{client_secret}"
        encoded_credentials = base64.b64encode(credentials.encode()).decode()

        # Prepare request parameters
        params = {
            'grant_type': 'authorization_code',
            'client_id': client_id,
            'code': request.code,
            'redirect_uri': request.redirect_uri,
            'code_verifier': request.code_verifier,
        }

        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization': f'Basic {encoded_credentials}',
        }

        logger.info("Exchanging authorization code for tokens")

        # Make token exchange request to Cognito
        async with httpx.AsyncClient() as client_http:
            response = await client_http.post(
                token_url,
                data=params,
                headers=headers,
                timeout=10.0
            )

        if response.status_code != 200:
            error_detail = response.text
            logger.error(f"Token exchange failed: {response.status_code}")

            # Parse error for better message
            try:
                error_json = response.json()
                if error_json.get('error') == 'invalid_grant':
                    raise HTTPException(
                        status_code=400,
                        detail="Authorization code is invalid or expired. Please try logging in again."
                    )
            except:
                pass

            raise HTTPException(
                status_code=response.status_code,
                detail=f"Token exchange failed: {error_detail}"
            )

        tokens = response.json()

        logger.info("Token exchange successful")

        return TokenExchangeResponse(
            id_token=tokens['id_token'],
            access_token=tokens['access_token'],
            refresh_token=tokens['refresh_token'],
            expires_in=tokens.get('expires_in', 3600),
            token_type=tokens.get('token_type', 'Bearer')
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error during token exchange: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Token exchange failed: {str(e)}"
        )


@router.post("/auth/refresh-token")
async def refresh_token(request: RefreshTokenRequest):
    """
    Refresh access and ID tokens using refresh token.

    Securely exchanges refresh token for new access/ID tokens
    using client secret stored on backend.
    """
    refresh_token = request.refresh_token
    try:
        # Get Cognito configuration
        cognito_domain, client_id, client_secret = get_cognito_config()

        token_url = f"https://{cognito_domain}/oauth2/token"

        # Create Basic Auth header
        credentials = f"{client_id}:{client_secret}"
        encoded_credentials = base64.b64encode(credentials.encode()).decode()

        params = {
            'grant_type': 'refresh_token',
            'client_id': client_id,
            'refresh_token': refresh_token,
        }

        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization': f'Basic {encoded_credentials}',
        }

        async with httpx.AsyncClient() as client:
            response = await client.post(
                token_url,
                data=params,
                headers=headers,
                timeout=10.0
            )

        if response.status_code != 200:
            raise HTTPException(
                status_code=response.status_code,
                detail=f"Token refresh failed: {response.text}"
            )

        tokens = response.json()

        return {
            'id_token': tokens['id_token'],
            'access_token': tokens['access_token'],
            'expires_in': tokens.get('expires_in', 3600),
            'token_type': tokens.get('token_type', 'Bearer')
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Token refresh failed: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Token refresh failed: {str(e)}"
        )
