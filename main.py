import uvicorn
from fastapi import Depends, FastAPI

from fastapi_keycloak import conf
from fastapi_keycloak.api import FastAPIKeycloak
from fastapi_keycloak.model import OIDCUser, UsernamePassword

app = FastAPI()
idp = FastAPIKeycloak(
    server_url=conf.KEYCLOAK_URL,
    client_id=conf.CLIENT_ID,
    client_secret=conf.CLIENT_SECRET,
    realm=conf.REALM,
    callback_uri=conf.CALLBACK_URI,
)
idp.add_swagger_config(app)


@app.get("/login_link", tags=["auth-flow"])
def login_link():
    return idp.login_uri


@app.get("/callback", tags=["auth-flow"])
def callback(session_state: str, code: str):
    return idp.exchange_authorization_code(
        session_state=session_state,
        code=code,
    )


@app.get("/logout_link", tags=["auth-flow"])
def logout_link():
    return idp.logout_uri


@app.get("/login", tags=["example-user-request"])
def login(user: UsernamePassword = Depends()):
    return idp.user_login(
        username=user.username, password=user.password.get_secret_value()
    )


@app.get("/admin", tags=["example-user-request"])
def admin(
    user: OIDCUser = Depends(idp.get_current_user(required_roles=["cloud_admin"])),
):
    return f"Hi premium user '{user}'"


@app.get("/operations", tags=["example-user-request"])
def operations(
    user: OIDCUser = Depends(idp.get_current_user(required_roles=["cloud_ops"])),
):
    return f"Hi operations user '{user}'"


@app.get("/protected", tags=["example-user-request"])
def protected(user: OIDCUser = Depends(idp.get_current_user())):
    return user


@app.get("/current_user/roles", tags=["example-user-request"])
def get_current_users_roles(user: OIDCUser = Depends(idp.get_current_user())):
    return user.roles


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8081)
