# OAuth 2.0 Authorization for Remote MCP Server

This Remote MCP server implements OAuth 2.0 authorization according to the MCP specification section 2-3-3, providing secure access control for Claude.ai and other clients.

## OAuth 2.0 Endpoints

### Authorization Server Metadata Discovery
```
GET /.well-known/oauth-authorization-server
```

Returns OAuth 2.0 authorization server metadata including supported endpoints, grant types, and scopes.

### Authorization Endpoint
```
GET /oauth/authorize
```

Parameters:
- `response_type` (required): Must be "code"
- `client_id` (required): Client identifier
- `redirect_uri` (required): Callback URI
- `scope` (optional): Space-separated list of scopes
- `state` (optional): State parameter for CSRF protection
- `code_challenge` (optional): PKCE code challenge
- `code_challenge_method` (optional): PKCE method ("plain" or "S256")

### Token Endpoint
```
POST /oauth/token
```

Supports three grant types:

#### Authorization Code Grant
Parameters:
- `grant_type`: "authorization_code"
- `code`: Authorization code from authorize endpoint
- `redirect_uri`: Same URI used in authorize request
- `client_id`: Client identifier
- `client_secret`: Client secret
- `code_verifier` (optional): PKCE code verifier

#### Refresh Token Grant
Parameters:
- `grant_type`: "refresh_token"
- `refresh_token`: Valid refresh token
- `client_id`: Client identifier
- `client_secret`: Client secret

#### Client Credentials Grant
Parameters:
- `grant_type`: "client_credentials"
- `client_id`: Client identifier
- `client_secret`: Client secret
- `scope` (optional): Requested scope

### Token Revocation Endpoint
```
POST /oauth/revoke
```

Parameters:
- `token`: Access token or refresh token to revoke
- `client_id`: Client identifier
- `client_secret`: Client secret

### Token Introspection Endpoint
```
POST /oauth/introspect
```

Parameters:
- `token`: Token to introspect
- `client_id`: Client identifier
- `client_secret`: Client secret

## Supported Scopes

- `mcp:tools` - Access to MCP tools (echo, system_info, calculator)
- `mcp:resources` - Access to MCP resources (system metrics, platform info)
- `mcp:prompts` - Access to MCP prompts
- `system:read` - Read system information
- `system:monitor` - Monitor system metrics

## Pre-configured Clients

### Claude.ai Client
- **Client ID**: `claude_ai_client`
- **Client Secret**: `claude_secret_key_2024`
- **Redirect URIs**: 
  - `https://claude.ai/oauth/callback`
  - `http://localhost:8080/callback`
  - `urn:ietf:wg:oauth:2.0:oob`
- **Scopes**: All scopes (mcp:tools, mcp:resources, mcp:prompts, system:read, system:monitor)

### Test Client
- **Client ID**: `mcp_test_client`
- **Client Secret**: `test_secret_key_2024`
- **Redirect URIs**: 
  - `http://localhost:5000/oauth/callback`
  - `urn:ietf:wg:oauth:2.0:oob`
- **Scopes**: mcp:tools, mcp:resources, system:read

## Protected Endpoints

Once authorized, access these protected MCP endpoints with Bearer token:

```
GET /mcp/protected/tools
POST /mcp/protected/call/{tool_name}
GET /mcp/protected/resources
```

## Usage Examples

### 1. Authorization Code Flow (for Claude.ai)

Step 1: Get authorization code
```
GET /oauth/authorize?response_type=code&client_id=claude_ai_client&redirect_uri=https://claude.ai/oauth/callback&scope=mcp:tools%20mcp:resources&state=random_state
```

Step 2: Exchange code for token
```bash
curl -X POST http://localhost:5000/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=AUTH_CODE&redirect_uri=https://claude.ai/oauth/callback&client_id=claude_ai_client&client_secret=claude_secret_key_2024"
```

Step 3: Use access token
```bash
curl -X GET http://localhost:5000/mcp/protected/tools \
  -H "Authorization: Bearer ACCESS_TOKEN"
```

### 2. Client Credentials Flow (for server-to-server)

```bash
curl -X POST http://localhost:5000/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=mcp_test_client&client_secret=test_secret_key_2024&scope=mcp:tools"
```

### 3. PKCE Flow (for public clients)

Step 1: Generate PKCE parameters
```javascript
// Generate code verifier (random string)
const codeVerifier = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))));

// Generate code challenge (SHA256 of verifier, base64url encoded)
const codeChallenge = btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(codeVerifier))))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
```

Step 2: Authorization request with PKCE
```
GET /oauth/authorize?response_type=code&client_id=mcp_test_client&redirect_uri=http://localhost:5000/oauth/callback&code_challenge=CODE_CHALLENGE&code_challenge_method=S256
```

Step 3: Exchange with code verifier
```bash
curl -X POST http://localhost:5000/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=AUTH_CODE&redirect_uri=http://localhost:5000/oauth/callback&client_id=mcp_test_client&code_verifier=CODE_VERIFIER"
```

## Token Management

### Refresh Token
```bash
curl -X POST http://localhost:5000/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token&refresh_token=REFRESH_TOKEN&client_id=claude_ai_client&client_secret=claude_secret_key_2024"
```

### Revoke Token
```bash
curl -X POST http://localhost:5000/oauth/revoke \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=ACCESS_TOKEN&client_id=claude_ai_client&client_secret=claude_secret_key_2024"
```

### Introspect Token
```bash
curl -X POST http://localhost:5000/oauth/introspect \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=ACCESS_TOKEN&client_id=claude_ai_client&client_secret=claude_secret_key_2024"
```

## MCP Specification Compliance

This implementation follows the MCP specification for authorization:

- **Section 2-3-3**: Fallbacks for servers without metadata discovery
- **OAuth 2.0 RFC 6749**: Authorization framework
- **RFC 7636**: PKCE extension for OAuth 2.0
- **RFC 7009**: Token revocation
- **RFC 7662**: Token introspection
- **RFC 8414**: Authorization server metadata

## Security Features

- **PKCE Support**: Prevents authorization code interception attacks
- **State Parameter**: CSRF protection for authorization flow
- **Secure Token Generation**: Cryptographically secure random tokens
- **Token Expiration**: Access tokens expire after 1 hour
- **Scope Validation**: Strict scope checking for all requests
- **Client Validation**: Comprehensive client credential verification

## Testing

Use the built-in test callback endpoint for development:
```
http://localhost:5000/oauth/callback
```

This endpoint displays the authorization code or error for testing purposes.

## Production Notes

For production deployment:

1. Use a proper database instead of in-memory storage
2. Implement user authentication and consent management
3. Use HTTPS for all OAuth endpoints
4. Implement proper logging and monitoring
5. Add rate limiting for token endpoints
6. Consider implementing JWT access tokens
7. Add proper client registration management