import uvicorn
from fastapi import Depends, FastAPI
from starlette.responses import RedirectResponse

from fastapi_keycloak.api import FastAPIKeycloak
from fastapi_keycloak.model import OIDCUser

app = FastAPI()
idp = FastAPIKeycloak(
    server_url="http://127.0.0.1:8085/auth",
    client_id="test-client",
    client_secret="eMWLOOjSuy64aA62QA3gYmnv94XgHlK8",
    realm="Test",
    callback_uri="http://localhost:8081/callback",
)
idp.add_swagger_config(app)


@app.get("/login")
def login_redirect():
    return RedirectResponse(idp.login_uri)


@app.get("/callback")
def callback(session_state: str, code: str):
    return idp.exchange_authorization_code(
        session_state=session_state,
        code=code,
    )  # This will return an access token


@app.get("/admin")
def admin(
    user: OIDCUser = Depends(
        idp.get_current_user(required_roles=["cloud_admin"])
    ),
):
    return f"Hi premium user '{user}'"


@app.get("/operations")
def operations(
    user: OIDCUser = Depends(
        idp.get_current_user(required_roles=["cloud_ops"])
    ),
):
    return f"Hi operations user '{user}'"


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8081)
