# MCP Test Server

A simple MCP server with **API Key**, **OAuth 2.0 Client Credentials**, and **OAuth 2.0 Authorization Code** authentication for testing the Appian MCP Connected System plugin.

## Live Server

**Base URL:** `https://web-production-80ec7.up.railway.app`

## Authentication Options

### 1. API Key Authentication
| Setting | Value |
|---------|-------|
| SSE URL | `https://web-production-80ec7.up.railway.app/sse` |
| API Key | `test-api-key-12345` |
| Header | `X-API-Key` or `Authorization: Bearer` |

### 2. OAuth 2.0 Client Credentials
| Setting | Value |
|---------|-------|
| SSE URL | `https://web-production-80ec7.up.railway.app/sse` |
| Token URL | `https://web-production-80ec7.up.railway.app/oauth/token` |
| Client ID | `test-client-id` |
| Client Secret | `test-client-secret` |
| Grant Type | `client_credentials` |

### 3. OAuth 2.0 Authorization Code
| Setting | Value |
|---------|-------|
| SSE URL | `https://web-production-80ec7.up.railway.app/sse` |
| Authorization URL | `https://web-production-80ec7.up.railway.app/oauth/authorize` |
| Token URL | `https://web-production-80ec7.up.railway.app/oauth/token` |
| Client ID | `test-client-id` |
| Client Secret | `test-client-secret` |
| Test Username | `testuser` |
| Test Password | `testpass` |

## Local Development

```bash
npm install
npm start
```

Local server runs at `http://localhost:3000`

## Testing

### Health Check
```bash
curl https://web-production-80ec7.up.railway.app/health
```

### API Key Auth
```bash
curl -N https://web-production-80ec7.up.railway.app/sse \
  -H "X-API-Key: test-api-key-12345"
```

### OAuth Client Credentials
```bash
# Get token
curl -X POST https://web-production-80ec7.up.railway.app/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=test-client-id&client_secret=test-client-secret"

# Connect to SSE
curl -N https://web-production-80ec7.up.railway.app/sse \
  -H "Authorization: Bearer <TOKEN>"
```

### OAuth Authorization Code
1. Open in browser: `https://web-production-80ec7.up.railway.app/oauth/authorize?client_id=test-client-id&redirect_uri=YOUR_REDIRECT_URI&response_type=code`
2. Login with `testuser` / `testpass`
3. Exchange the code for a token at `/oauth/token` with `grant_type=authorization_code`

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3000` | Server port |
| `OAUTH_CLIENT_ID` | `test-client-id` | OAuth client ID |
| `OAUTH_CLIENT_SECRET` | `test-client-secret` | OAuth client secret |

## Features

- ✅ API Key authentication
- ✅ OAuth 2.0 Client Credentials grant
- ✅ OAuth 2.0 Authorization Code grant
- ✅ Refresh token support
- ✅ MCP protocol over SSE
- ✅ Sample tool: `echo`
- ✅ Sample resource: `test://example`
- ✅ Health check endpoint
