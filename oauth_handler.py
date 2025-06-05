#!/usr/bin/env python3
"""
OAuth 2.0 Authorization Handler for MCP Server
Implements MCP specification for authorization
"""

import secrets
import time
import hashlib
import base64
import json
import urllib.parse
import logging
from typing import Dict, Optional, Any
from dataclasses import dataclass
from datetime import datetime, timedelta

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


@dataclass
class AuthorizationCode:
    """Authorization code data structure"""
    code: str
    client_id: str
    redirect_uri: str
    scope: str
    challenge: Optional[str]
    challenge_method: Optional[str]
    expires_at: float
    user_id: Optional[str] = None


@dataclass
class AccessToken:
    """Access token data structure"""
    token: str
    client_id: str
    scope: str
    expires_at: float
    refresh_token: Optional[str] = None
    user_id: Optional[str] = None


class OAuth2Handler:
    """OAuth 2.0 handler for MCP server authorization"""

    def __init__(self):
        # In-memory storage (use database in production)
        self.authorization_codes: Dict[str, AuthorizationCode] = {}
        self.access_tokens: Dict[str, AccessToken] = {}
        self.refresh_tokens: Dict[str,
                                  str] = {}  # refresh_token -> access_token

        # OAuth 2.0 configuration
        self.authorization_endpoint = "/oauth/authorize"
        self.token_endpoint = "/oauth/token"
        self.revocation_endpoint = "/oauth/revoke"
        self.introspection_endpoint = "/oauth/introspect"

        # Supported grant types
        self.supported_grant_types = [
            "authorization_code", "refresh_token", "client_credentials"
        ]

        # Supported response types
        self.supported_response_types = ["code"]

        # Supported scopes
        self.supported_scopes = [
            "mcp:tools", "mcp:resources", "mcp:prompts", "system:read",
            "system:monitor", "claudeai", "read", "write", "admin"
        ]

        # Multiple client ID formats supported for maximum compatibility
        self.clients = {
            # UUID format for strict validation environments
            "550e8400-e29b-41d4-a716-446655440000": {
                "client_secret":
                "claude_secret_key_2024",
                "redirect_uris": [
                    "https://claude.ai/oauth/callback",
                    "http://localhost:8080/callback",
                    "http://localhost:5000/oauth/callback",
                    "urn:ietf:wg:oauth:2.0:oob"
                ],
                "grant_types":
                ["authorization_code", "refresh_token", "client_credentials"],
                "response_types": ["code"],
                "scope":
                "mcp:tools mcp:resources mcp:prompts system:read system:monitor read write admin"
            },
            # String format for legacy compatibility
            "claude_ai_client": {
                "client_secret":
                "claude_secret_key_2024",
                "redirect_uris": [
                    "https://claude.ai/oauth/callback",
                    "http://localhost:8080/callback",
                    "http://localhost:5000/oauth/callback",
                    "urn:ietf:wg:oauth:2.0:oob"
                ],
                "grant_types":
                ["authorization_code", "refresh_token", "client_credentials"],
                "response_types": ["code"],
                "scope":
                "mcp:tools mcp:resources mcp:prompts system:read system:monitor read write admin"
            },
            # Test client with UUID format
            "660e8400-e29b-41d4-a716-446655440001": {
                "client_secret":
                "test_secret_key_2024",
                "redirect_uris": [
                    "http://localhost:5000/oauth/callback",
                    "urn:ietf:wg:oauth:2.0:oob"
                ],
                "grant_types":
                ["authorization_code", "refresh_token", "client_credentials"],
                "response_types": ["code"],
                "scope":
                "mcp:tools mcp:resources system:read"
            },
            # Test client with string format
            "mcp_test_client": {
                "client_secret":
                "test_secret_key_2024",
                "redirect_uris": [
                    "http://localhost:5000/oauth/callback",
                    "urn:ietf:wg:oauth:2.0:oob"
                ],
                "grant_types":
                ["authorization_code", "refresh_token", "client_credentials"],
                "response_types": ["code"],
                "scope":
                "mcp:tools mcp:resources system:read"
            }
        }

    def generate_authorization_code(self) -> str:
        """Generate secure authorization code"""
        return secrets.token_urlsafe(32)

    def generate_access_token(self) -> str:
        """Generate secure access token"""
        return secrets.token_urlsafe(32)

    def generate_refresh_token(self) -> str:
        """Generate secure refresh token"""
        return secrets.token_urlsafe(32)

    def verify_pkce_challenge(self, verifier: str, challenge: str,
                              method: str) -> bool:
        """Verify PKCE code challenge"""
        if method == "plain":
            return verifier == challenge
        elif method == "S256":
            # SHA256 hash and base64url encode
            digest = hashlib.sha256(verifier.encode()).digest()
            challenge_computed = base64.urlsafe_b64encode(
                digest).decode().rstrip('=')
            return challenge_computed == challenge
        return False

    def validate_client(self,
                        client_id: str,
                        client_secret: Optional[str] = None) -> bool:
        """Validate client credentials"""
        logger.debug(
            f"validate_client called with client_id='{client_id}', client_secret={'present' if client_secret else 'None'}"
        )

        # Normalize client_id - handle both UUID and string formats
        normalized_client_id = str(client_id).strip()
        logger.debug(f"Normalized client_id: '{normalized_client_id}'")

        # Check if client exists in predefined clients
        if normalized_client_id in self.clients:
            logger.debug(
                f"Client '{normalized_client_id}' found in predefined clients")
            if client_secret is not None:
                result = self.clients[normalized_client_id][
                    "client_secret"] == client_secret
                logger.debug(f"Secret validation result: {result}")
                return result
            logger.debug("No secret required for predefined client")
            return True

        # Accept Claude.ai dynamic client IDs that start with "client_"
        if normalized_client_id.startswith("client_"):
            logger.debug(
                f"Accepting Claude.ai dynamic client: '{normalized_client_id}'"
            )
            return True

        logger.debug(f"Client '{normalized_client_id}' not recognized")
        return False

    def validate_redirect_uri(self, client_id: str, redirect_uri: str) -> bool:
        """Validate redirect URI"""
        logger.debug(
            f"validate_redirect_uri called with client_id='{client_id}', redirect_uri='{redirect_uri}'"
        )

        # Check predefined clients
        if client_id in self.clients:
            result = redirect_uri in self.clients[client_id]["redirect_uris"]
            logger.debug(f"Predefined client redirect validation: {result}")
            return result

        # For Claude.ai dynamic clients, allow common Claude.ai redirect URIs
        if client_id.startswith("client_"):
            allowed_claude_uris = [
                "https://claude.ai/oauth/callback",
                "https://claude.ai/callback",
                "https://claude.anthropic.com/oauth/callback",
                "https://claude.anthropic.com/callback",
                "urn:ietf:wg:oauth:2.0:oob"
            ]
            result = redirect_uri in allowed_claude_uris
            logger.debug(
                f"Claude.ai dynamic client redirect validation: {result}, allowed URIs: {allowed_claude_uris}"
            )
            return result

        logger.debug(
            f"Redirect URI validation failed for client_id='{client_id}'")
        return False

    def validate_scope(self, requested_scope: str, client_id: str) -> bool:
        """Validate requested scope"""
        logger.debug(
            f"validate_scope called with requested_scope='{requested_scope}', client_id='{client_id}'"
        )

        if not requested_scope:
            logger.debug("Empty scope, allowing")
            return True

        # For Claude.ai clients (both UUID, string format, and dynamic client_ format), allow any scope
        claude_clients = [
            "550e8400-e29b-41d4-a716-446655440000", "claude_ai_client"
        ]
        if client_id in claude_clients or client_id.startswith("client_"):
            logger.debug(
                f"Claude.ai client '{client_id}' detected, allowing all scopes"
            )
            return True

        client_scope = self.clients.get(client_id, {}).get("scope", "")
        client_scopes = set(client_scope.split())
        requested_scopes = set(requested_scope.split())

        logger.debug(f"Client scopes: {client_scopes}")
        logger.debug(f"Requested scopes: {requested_scopes}")
        logger.debug(f"Supported scopes: {self.supported_scopes}")

        # Check if all requested scopes are subset of client allowed scopes
        # or if they are in the globally supported scopes
        result = (requested_scopes.issubset(client_scopes)
                  or requested_scopes.issubset(set(self.supported_scopes)))
        logger.debug(f"Scope validation result: {result}")
        return result

    def create_authorization_code(self,
                                  client_id: str,
                                  redirect_uri: str,
                                  scope: str,
                                  challenge: Optional[str] = None,
                                  challenge_method: Optional[str] = None,
                                  user_id: Optional[str] = None) -> str:
        """Create authorization code"""
        code = self.generate_authorization_code()
        expires_at = time.time() + 600  # 10 minutes

        auth_code = AuthorizationCode(code=code,
                                      client_id=client_id,
                                      redirect_uri=redirect_uri,
                                      scope=scope,
                                      challenge=challenge,
                                      challenge_method=challenge_method,
                                      expires_at=expires_at,
                                      user_id=user_id)

        self.authorization_codes[code] = auth_code
        return code

    def exchange_authorization_code(
            self,
            code: str,
            client_id: str,
            client_secret: Optional[str],
            redirect_uri: str,
            code_verifier: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Exchange authorization code for access token"""
        logger.info("=== Token Exchange Started ===")
        logger.info(
            f"Token exchange params: code='{code}', client_id='{client_id}', redirect_uri='{redirect_uri}'"
        )

        # Validate authorization code
        if code not in self.authorization_codes:
            logger.error(f"Authorization code not found: {code}")
            return None

        auth_code = self.authorization_codes[code]
        logger.info(f"Found auth code for client: {auth_code.client_id}")

        # Check expiration
        if time.time() > auth_code.expires_at:
            logger.error(f"Authorization code expired: {code}")
            del self.authorization_codes[code]
            return None

        # Validate client - for Claude.ai dynamic clients, skip secret validation
        logger.info("Validating client for token exchange...")
        if client_id.startswith("client_"):
            logger.info(
                "Claude.ai dynamic client detected, skipping secret validation"
            )
            if not self.validate_client(client_id):
                logger.error(
                    f"Claude.ai client validation failed: {client_id}")
                return None
        else:
            logger.info("Predefined client detected, validating with secret")
            if not self.validate_client(client_id, client_secret):
                logger.error(
                    f"Predefined client validation failed: {client_id}")
                return None

        # Validate redirect URI
        if auth_code.redirect_uri != redirect_uri:
            logger.error(
                f"Redirect URI mismatch: expected={auth_code.redirect_uri}, got={redirect_uri}"
            )
            return None

        # Validate client ID
        if auth_code.client_id != client_id:
            logger.error(
                f"Client ID mismatch: expected={auth_code.client_id}, got={client_id}"
            )
            return None

        # Validate PKCE if used
        if auth_code.challenge and code_verifier:
            if not self.verify_pkce_challenge(
                    code_verifier, auth_code.challenge,
                    auth_code.challenge_method or "plain"):
                return None

        # Generate tokens
        access_token = self.generate_access_token()
        refresh_token = self.generate_refresh_token()
        expires_in = 3600  # 1 hour
        expires_at = time.time() + expires_in

        # Store access token
        token_obj = AccessToken(token=access_token,
                                client_id=client_id,
                                scope=auth_code.scope,
                                expires_at=expires_at,
                                refresh_token=refresh_token,
                                user_id=auth_code.user_id)

        self.access_tokens[access_token] = token_obj
        self.refresh_tokens[refresh_token] = access_token

        # Clean up authorization code
        del self.authorization_codes[code]

        return {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": expires_in,
            "refresh_token": refresh_token,
            "scope": auth_code.scope
        }

    def refresh_access_token(self, refresh_token: str, client_id: str,
                             client_secret: str) -> Optional[Dict[str, Any]]:
        """Refresh access token"""

        # Validate client
        if not self.validate_client(client_id, client_secret):
            return None

        # Find access token by refresh token
        if refresh_token not in self.refresh_tokens:
            return None

        old_access_token = self.refresh_tokens[refresh_token]
        if old_access_token not in self.access_tokens:
            return None

        old_token_obj = self.access_tokens[old_access_token]

        # Validate client ID
        if old_token_obj.client_id != client_id:
            return None

        # Generate new tokens
        new_access_token = self.generate_access_token()
        new_refresh_token = self.generate_refresh_token()
        expires_in = 3600  # 1 hour
        expires_at = time.time() + expires_in

        # Create new token object
        new_token_obj = AccessToken(token=new_access_token,
                                    client_id=client_id,
                                    scope=old_token_obj.scope,
                                    expires_at=expires_at,
                                    refresh_token=new_refresh_token,
                                    user_id=old_token_obj.user_id)

        # Update storage
        self.access_tokens[new_access_token] = new_token_obj
        self.refresh_tokens[new_refresh_token] = new_access_token

        # Clean up old tokens
        del self.access_tokens[old_access_token]
        del self.refresh_tokens[refresh_token]

        return {
            "access_token": new_access_token,
            "token_type": "Bearer",
            "expires_in": expires_in,
            "refresh_token": new_refresh_token,
            "scope": old_token_obj.scope
        }

    def client_credentials_grant(self, client_id: str, client_secret: str,
                                 scope: str) -> Optional[Dict[str, Any]]:
        """Client credentials grant"""

        # Validate client
        if not self.validate_client(client_id, client_secret):
            return None

        # Validate scope
        if not self.validate_scope(scope, client_id):
            return None

        # Generate access token
        access_token = self.generate_access_token()
        expires_in = 3600  # 1 hour
        expires_at = time.time() + expires_in

        # Store access token
        token_obj = AccessToken(token=access_token,
                                client_id=client_id,
                                scope=scope,
                                expires_at=expires_at)

        self.access_tokens[access_token] = token_obj

        return {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": expires_in,
            "scope": scope
        }

    def validate_access_token(self,
                              access_token: str) -> Optional[AccessToken]:
        """Validate access token"""
        if access_token not in self.access_tokens:
            return None

        token_obj = self.access_tokens[access_token]

        # Check expiration
        if time.time() > token_obj.expires_at:
            # Clean up expired token
            if token_obj.refresh_token:
                self.refresh_tokens.pop(token_obj.refresh_token, None)
            del self.access_tokens[access_token]
            return None

        return token_obj

    def revoke_token(self, token: str, client_id: str,
                     client_secret: str) -> bool:
        """Revoke access or refresh token"""

        # Validate client
        if not self.validate_client(client_id, client_secret):
            return False

        # Try to revoke as access token
        if token in self.access_tokens:
            token_obj = self.access_tokens[token]
            if token_obj.client_id == client_id:
                # Clean up refresh token too
                if token_obj.refresh_token:
                    self.refresh_tokens.pop(token_obj.refresh_token, None)
                del self.access_tokens[token]
                return True

        # Try to revoke as refresh token
        if token in self.refresh_tokens:
            access_token = self.refresh_tokens[token]
            if access_token in self.access_tokens:
                token_obj = self.access_tokens[access_token]
                if token_obj.client_id == client_id:
                    del self.access_tokens[access_token]
                    del self.refresh_tokens[token]
                    return True

        return False

    def introspect_token(self, token: str, client_id: str,
                         client_secret: str) -> Dict[str, Any]:
        """Introspect token"""

        # Validate client
        if not self.validate_client(client_id, client_secret):
            return {"active": False}

        token_obj = self.validate_access_token(token)
        if not token_obj:
            return {"active": False}

        return {
            "active": True,
            "client_id": token_obj.client_id,
            "scope": token_obj.scope,
            "exp": int(token_obj.expires_at),
            "iat": int(token_obj.expires_at - 3600),  # Issued 1 hour ago
            "token_type": "Bearer",
            "sub": token_obj.user_id
        }

    def get_authorization_server_metadata(self) -> Dict[str, Any]:
        """Get OAuth 2.0 authorization server metadata"""
        return {
            #"issuer":
            #"https://mcp-server.example.com",
            "authorization_endpoint":
            self.authorization_endpoint,
            "token_endpoint":
            self.token_endpoint,
            "revocation_endpoint":
            self.revocation_endpoint,
            "introspection_endpoint":
            self.introspection_endpoint,
            "response_types_supported":
            self.supported_response_types,
            "grant_types_supported":
            self.supported_grant_types,
            "scopes_supported":
            self.supported_scopes,
            "token_endpoint_auth_methods_supported":
            ["client_secret_basic", "client_secret_post"],
            "code_challenge_methods_supported": ["plain", "S256"],
            "revocation_endpoint_auth_methods_supported":
            ["client_secret_basic", "client_secret_post"],
            "introspection_endpoint_auth_methods_supported":
            ["client_secret_basic", "client_secret_post"]
        }

    def cleanup_expired_tokens(self):
        """Clean up expired tokens (should be run periodically)"""
        current_time = time.time()

        # Clean expired authorization codes
        expired_codes = [
            code for code, auth_code in self.authorization_codes.items()
            if current_time > auth_code.expires_at
        ]
        for code in expired_codes:
            del self.authorization_codes[code]

        # Clean expired access tokens
        expired_tokens = [
            token for token, token_obj in self.access_tokens.items()
            if current_time > token_obj.expires_at
        ]
        for token in expired_tokens:
            token_obj = self.access_tokens[token]
            if token_obj.refresh_token:
                self.refresh_tokens.pop(token_obj.refresh_token, None)
            del self.access_tokens[token]


# Global OAuth handler instance
oauth_handler = OAuth2Handler()
