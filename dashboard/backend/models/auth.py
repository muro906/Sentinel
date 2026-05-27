"""Authentication-related Pydantic models."""

from pydantic import BaseModel


class TokenResponse(BaseModel):
    """OAuth2 token response model.
    
    Attributes:
        access_token: The JWT access token string.
        token_type: The token type (always 'bearer').
    """
    access_token: str
    token_type: str