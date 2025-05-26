import logging
import secrets
from typing import Any, Dict, Optional
from urllib.parse import urlencode

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from starlette.middleware.sessions import SessionMiddleware

# Configuration
SSO_LOGIN_URL = "https://login.ubuntu.com"
SSO_TEAM = "canonical-webmonkeys"
SECRET_KEY = secrets.token_urlsafe(32)

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Demo Platform Session Manager")
app.add_middleware(
    SessionMiddleware,
    secret_key=SECRET_KEY,
    domain=".myapp.local",
)
# In-memory session storage for simplicity
sessions: Dict[str, Dict[str, Any]] = {}


class OpenIDAuth:
    def __init__(self):
        self.discovery_url = (
            f"{SSO_LOGIN_URL}/.well-known/openid_configuration"
        )
        self.client_id = "demo-platform"

    async def get_openid_config(self):
        """Get OpenID configuration from Ubuntu SSO"""
        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(self.discovery_url)
                return response.json()
            except Exception as e:
                logger.error(f"Failed to get OpenID config: {e}")
                return None

    def build_auth_url(self, redirect_uri: str, state: str) -> str:
        """Build the authorization URL for Ubuntu SSO"""
        params = {
            "openid.mode": "checkid_setup",
            "openid.ns": "http://specs.openid.net/auth/2.0",
            "openid.identity": "http://specs.openid.net/auth/2.0/identifier_select",
            "openid.claimed_id": "http://specs.openid.net/auth/2.0/identifier_select",
            "openid.return_to": redirect_uri,
            "openid.realm": redirect_uri.split("/callback")[0],
            "openid.ns.sreg": "http://openid.net/extensions/sreg/1.1",
            "openid.sreg.required": "email",
            "openid.ns.lp": "http://ns.launchpad.net/2007/openid-teams",
            "openid.lp.query_membership": SSO_TEAM,
        }
        return f"{SSO_LOGIN_URL}/+openid?{urlencode(params)}"

    async def verify_response(
        self, request: Request
    ) -> Optional[Dict[str, Any]]:
        """Verify the OpenID response from Ubuntu SSO"""
        params = dict(request.query_params)

        # Check if this is a positive response
        if params.get("openid.mode") != "id_res":
            return None

        # Verify the response by checking with SSO
        verify_params = params.copy()
        verify_params["openid.mode"] = "check_authentication"

        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(
                    SSO_LOGIN_URL + "/+openid", data=verify_params
                )
                if "is_valid:true" not in response.text:
                    logger.error("OpenID verification failed")
                    return None

                # Check team membership
                team_membership = params.get("openid.lp.is_member", "")
                if SSO_TEAM not in team_membership:
                    logger.error(f"User not member of {SSO_TEAM}")
                    return None

                return {
                    "identity_url": params.get("openid.identity"),
                    "email": params.get("openid.sreg.email"),
                    "teams": team_membership.split(",")
                    if team_membership
                    else [],
                }
            except Exception as e:
                logger.error(f"Verification failed: {e}")
                return None


openid_auth = OpenIDAuth()


@app.get("/login")
async def login(request: Request, next_url: str = "/"):
    """Initiate OpenID login flow"""
    # Check if already logged in
    if "user" in request.session:
        return RedirectResponse(url=next_url)

    # Generate state for CSRF protection
    state = secrets.token_urlsafe(32)
    request.session["oauth_state"] = state
    request.session["next_url"] = next_url

    # Build redirect URI
    redirect_uri = f"{request.url.scheme}://{request.url.netloc}/callback"

    # Build auth URL
    auth_url = openid_auth.build_auth_url(redirect_uri, state)

    return RedirectResponse(url=auth_url)


@app.get("/callback")
async def callback(request: Request):
    """Handle OpenID callback"""
    try:
        # Verify the OpenID response
        user_info = await openid_auth.verify_response(request)

        if not user_info:
            raise HTTPException(
                status_code=403, detail="Authentication failed"
            )

        # Store user in session
        request.session["user"] = user_info

        # Get the next URL and redirect
        next_url = request.session.pop("next_url", "/")

        return RedirectResponse(url=next_url)

    except Exception as e:
        logger.error(f"Callback error: {e}")
        raise HTTPException(
            status_code=400, detail="Authentication callback failed"
        )


@app.get("/logout")
async def logout(request: Request):
    """Logout and clear session"""
    request.session.clear()
    return RedirectResponse(url="/")


@app.get("/verify-and-inject")
async def verify_and_inject(request: Request):
    """Endpoint for Nginx auth_request module"""
    user = request.session.get("user")

    if not user:
        return JSONResponse(
            status_code=401, content={"error": "Not authenticated"}
        )

    # Return user info with headers for injection
    headers = {
        "X-User-Email": user["email"],
        "X-User-Identity": user["identity_url"],
        "X-Authenticated": "true",
    }
    return JSONResponse(content={"authenticated": True}, headers=headers)


@app.get("/user")
async def get_user(request: Request):
    """Get current user info"""
    user = request.session.get("user")
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    return {"user": user}


@app.get("/health")
async def health():
    """Health check endpoint"""
    return {"status": "healthy"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8080)
