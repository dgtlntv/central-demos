import logging
import secrets
from typing import Any, Dict

from django_openid_auth.teams import TeamsRequest, TeamsResponse
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from openid.consumer import consumer
from openid.consumer.discover import DiscoveryFailure
from openid.extensions import sreg
from openid.store.memstore import MemoryStore
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

# OpenID store and session storage
openid_store = MemoryStore()
openid_sessions: Dict[str, Dict[str, Any]] = {}


class OpenIDAuth:
    def __init__(self):
        self.store = openid_store
        self.sso_url = SSO_LOGIN_URL
        self.team = SSO_TEAM

    def _get_session_id(self, request: Request) -> str:
        """Get or create a session ID for OpenID"""
        if "openid_session_id" not in request.session:
            request.session["openid_session_id"] = secrets.token_urlsafe(32)
        return request.session["openid_session_id"]

    def _get_openid_session(self, request: Request) -> Dict[str, Any]:
        """Get OpenID session storage"""
        session_id = self._get_session_id(request)
        if session_id not in openid_sessions:
            openid_sessions[session_id] = {}
        return openid_sessions[session_id]

    def get_consumer(self, request: Request):
        """Get OpenID consumer instance"""
        openid_session = self._get_openid_session(request)
        return consumer.Consumer(openid_session, self.store)

    def build_trust_root(self, request: Request) -> str:
        """Build trust root URL"""
        return f"{request.url.scheme}://{request.url.netloc}"

    def build_return_to(self, request: Request) -> str:
        """Build return URL"""
        return f"{request.url.scheme}://{request.url.netloc}/callback"

    async def initiate_login(self, request: Request) -> str:
        """Initiate OpenID login and return redirect URL"""
        try:
            # Create OpenID consumer
            oid_consumer = self.get_consumer(request)

            # Begin OpenID authentication
            auth_request = oid_consumer.begin(self.sso_url)

            # Add Simple Registration extension for email
            sreg_request = sreg.SRegRequest(required=["email"])
            auth_request.addExtension(sreg_request)

            # Add teams extension for team membership
            teams_request = TeamsRequest(query_membership=[self.team])
            auth_request.addExtension(teams_request)

            # Build URLs
            trust_root = self.build_trust_root(request)
            return_to = self.build_return_to(request)

            # Get redirect URL
            return auth_request.redirectURL(trust_root, return_to)

        except DiscoveryFailure as e:
            logger.error(f"OpenID discovery failed: {e}")
            raise HTTPException(
                status_code=500, detail="Authentication service unavailable"
            )
        except Exception as e:
            logger.error(f"Login initiation error: {e}")
            raise HTTPException(status_code=500, detail="Login failed")

    async def handle_callback(self, request: Request) -> Dict[str, Any]:
        """Handle OpenID callback and return user info"""
        try:
            # Create OpenID consumer
            oid_consumer = self.get_consumer(request)

            # Get current URL for verification
            current_url = f"{request.url.scheme}://{request.url.netloc}{request.url.path}?{request.url.query}"

            # Complete the authentication
            response = oid_consumer.complete(
                dict(request.query_params), current_url
            )

            if response.status == consumer.SUCCESS:
                # Check team membership
                teams_response = TeamsResponse.fromSuccessResponse(response)
                if (
                    teams_response
                    and self.team not in teams_response.is_member
                ):
                    logger.error(f"User not member of {self.team}")
                    raise HTTPException(
                        status_code=403,
                        detail="Access denied - not a team member",
                    )

                # Get user info from Simple Registration extension
                sreg_response = sreg.SRegResponse.fromSuccessResponse(response)
                email = sreg_response.get("email") if sreg_response else None

                # Return user info
                return {
                    "identity_url": response.identity_url,
                    "email": email,
                    "teams": teams_response.is_member
                    if teams_response
                    else [],
                }

            elif response.status == consumer.CANCEL:
                raise HTTPException(
                    status_code=400, detail="Authentication cancelled"
                )
            elif response.status == consumer.FAILURE:
                logger.error(
                    f"OpenID authentication failed: {response.message}"
                )
                raise HTTPException(
                    status_code=403, detail="Authentication failed"
                )
            else:
                raise HTTPException(
                    status_code=400, detail="Unknown authentication status"
                )

        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Callback handling error: {e}")
            raise HTTPException(
                status_code=400, detail="Authentication callback failed"
            )


openid_auth = OpenIDAuth()


def login_required(request: Request):
    """Dependency that checks if user is logged in"""
    user = request.session.get("user")
    if not user:
        # Store current URL for redirect after login
        next_url = str(request.url)
        raise HTTPException(
            status_code=401,
            detail=f"Not authenticated. Please login at /login?next_url={next_url}",
        )
    return user


@app.get("/login")
async def login(request: Request, next: str = "/", next_url: str = None):
    """Initiate OpenID login flow"""
    # Use next_url if provided (from nginx), otherwise use next
    redirect_after_login = next_url or next

    # Check if already logged in
    if "user" in request.session:
        return RedirectResponse(url=redirect_after_login)

    # Store next URL for after login
    request.session["next_url"] = redirect_after_login

    # Get redirect URL from OpenID auth handler
    auth_url = await openid_auth.initiate_login(request)
    return RedirectResponse(url=auth_url)


@app.get("/callback")
async def callback(request: Request):
    """Handle OpenID callback"""
    # Handle callback through OpenID auth handler
    user_info = await openid_auth.handle_callback(request)

    # Store user in session
    request.session["user"] = user_info

    # Redirect to next URL
    next_url = request.session.pop("next_url", "/")
    return RedirectResponse(url=next_url)


@app.get("/logout")
async def logout(request: Request):
    """Logout and clear session"""
    request.session.clear()
    return RedirectResponse(url="/")


@app.get("/verify-and-inject")
async def verify_and_inject(user: dict = Depends(login_required)):
    """Endpoint for Nginx auth_request module"""
    # Return user info with headers for injection
    headers = {
        "X-User-Email": user.get("email", ""),
        "X-User-Identity": user.get("identity_url", ""),
        "X-Authenticated": "true",
    }
    return JSONResponse(content={"authenticated": True}, headers=headers)


@app.get("/user")
async def get_user(user: dict = Depends(login_required)):
    """Get current user info"""
    return {"user": user}


@app.get("/protected")
async def protected_route(user: dict = Depends(login_required)):
    """Example protected route"""
    return {"message": f"Hello {user.get('email', 'user')}!", "user": user}


@app.get("/health")
async def health():
    """Health check endpoint"""
    return {"status": "healthy"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8080)
