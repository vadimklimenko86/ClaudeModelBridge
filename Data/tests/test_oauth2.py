"""
Тесты для OAuth2 Manager
"""

import pytest
import json
from starlette.testclient import TestClient
from starlette.applications import Starlette
from oauth2 import OAuth2Manager
import logging


@pytest.fixture
def oauth_manager():
    """Создание экземпляра OAuth2Manager для тестов"""
    logger = logging.getLogger("test")
    return OAuth2Manager(logger)


@pytest.fixture
def test_app(oauth_manager):
    """Создание тестового приложения"""
    app = Starlette(routes=oauth_manager.routes)
    return app


@pytest.fixture
def client(test_app):
    """Создание тестового клиента"""
    return TestClient(test_app)


class TestOAuth2Metadata:
    """Тесты для метаданных OAuth2"""
    
    def test_authorization_server_metadata(self, client):
        """Тест получения метаданных сервера авторизации"""
        response = client.get("/.well-known/oauth-authorization-server")
        assert response.status_code == 200
        
        data = response.json()
        assert "issuer" in data
        assert "authorization_endpoint" in data
        assert "token_endpoint" in data
        assert "jwks_uri" in data
        
    def test_jwks_endpoint(self, client):
        """Тест получения JWKS"""
        response = client.get("/.well-known/jwks.json")
        assert response.status_code == 200
        
        data = response.json()
        assert "keys" in data
        assert len(data["keys"]) > 0
        assert data["keys"][0]["kty"] == "RSA"


class TestAuthorizationFlow:
    """Тесты для Authorization Code Flow"""
    
    def test_authorization_request_missing_params(self, client):
        """Тест запроса авторизации без параметров"""
        response = client.get("/oauth/authorize")
        assert response.status_code == 400
        
    def test_authorization_request_invalid_client(self, client):
        """Тест запроса авторизации с неверным client_id"""
        response = client.get("/oauth/authorize", params={
            "client_id": "invalid_client",
            "redirect_uri": "https://example.com/callback",
            "response_type": "code"
        })
        assert response.status_code == 400
        assert "invalid_client" in response.json()["error"]
        
    def test_authorization_request_invalid_redirect_uri(self, client):
        """Тест запроса авторизации с неверным redirect_uri"""
        response = client.get("/oauth/authorize", params={
            "client_id": "client_1749051312",
            "redirect_uri": "https://invalid.com/callback",
            "response_type": "code"
        })
        assert response.status_code == 400
        assert "invalid_redirect_uri" in response.json()["error"]


class TestTokenEndpoint:
    """Тесты для token endpoint"""
    
    def test_token_request_invalid_grant_type(self, client):
        """Тест запроса токена с неверным grant_type"""
        response = client.post("/oauth/token", data={
            "grant_type": "invalid_grant"
        })
        assert response.status_code == 400
        assert "unsupported_grant_type" in response.json()["error"]
        
    def test_token_request_missing_code(self, client):
        """Тест запроса токена без кода"""
        response = client.post("/oauth/token", data={
            "grant_type": "authorization_code",
            "client_id": "client_1749051312",
            "redirect_uri": "https://claude.ai/oauth/callback"
        })
        assert response.status_code == 400
        assert "invalid_request" in response.json()["error"]


class TestUserInfo:
    """Тесты для userinfo endpoint"""
    
    def test_userinfo_without_token(self, client):
        """Тест запроса userinfo без токена"""
        response = client.get("/oauth/userinfo")
        assert response.status_code == 401
        assert "invalid_token" in response.json()["error"]
        
    def test_userinfo_with_invalid_token(self, client):
        """Тест запроса userinfo с неверным токеном"""
        response = client.get("/oauth/userinfo", headers={
            "Authorization": "Bearer invalid_token"
        })
        assert response.status_code == 401
        assert "invalid_token" in response.json()["error"]


class TestPKCE:
    """Тесты для PKCE"""
    
    def test_pkce_verification(self, oauth_manager):
        """Тест проверки PKCE"""
        # Тест с методом plain
        assert oauth_manager._verify_pkce("test_verifier", "test_verifier", "plain")
        assert not oauth_manager._verify_pkce("test_verifier", "wrong_challenge", "plain")
        
        # Тест с методом S256
        import hashlib
        import base64
        
        verifier = "test_verifier_123"
        challenge = base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode()).digest()
        ).decode().rstrip('=')
        
        assert oauth_manager._verify_pkce(verifier, challenge, "S256")
        assert not oauth_manager._verify_pkce("wrong_verifier", challenge, "S256")
