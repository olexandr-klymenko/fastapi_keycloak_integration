from __future__ import annotations

import functools
import json
from json import JSONDecodeError
from typing import Callable, List, Type
from urllib.parse import urlencode

import requests
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import ExpiredSignatureError, JWTError, jwt
from jose.exceptions import JWTClaimsError
from pydantic import BaseModel
from requests import Response

from .exceptions import KeycloakError
from .model import KeycloakToken, OIDCUser


def result_or_error(
    response_model: Type[BaseModel] = None, is_list: bool = False
) -> List[BaseModel] or BaseModel or KeycloakError:
    """Decorator used to ease the handling of responses from Keycloak.

    Args:
        response_model (Type[BaseModel]): Object that should be returned based on the payload
        is_list (bool): True if the return value should be a list of the response model provided

    Returns:
        BaseModel or List[BaseModel]: Based on the given signature and response circumstances

    Raises:
        KeycloakError: If the resulting response is not a successful HTTP-Code (>299)

    Notes:
        - Keycloak sometimes returns empty payloads but describes the error in its content (byte encoded)
          which is why this function checks for JSONDecode exceptions.
        - Keycloak often does not expose the real error for security measures. You will most likely encounter:
          {'error': 'unknown_error'} as a result. If so, please check the logs of your Keycloak instance to get error
          details, the RestAPI doesn't provide any.
    """

    def inner(f):
        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            def create_list(json_data: List[dict]):
                return [response_model.parse_obj(entry) for entry in json_data]

            def create_object(json_data: dict):
                return response_model.parse_obj(json_data)

            result: Response = f(*args, **kwargs)  # The actual call

            if (
                type(result) != Response
            ):  # If the object given is not a response object, directly return it.
                return result

            if result.status_code in range(100, 299):  # Successful
                if response_model is None:  # No model given

                    try:
                        return result.json()
                    except JSONDecodeError:
                        return result.content.decode("utf-8")

                else:  # Response model given
                    if is_list:
                        return create_list(result.json())
                    else:
                        return create_object(result.json())

            else:  # Not Successful, forward status code and error
                try:
                    raise KeycloakError(
                        status_code=result.status_code, reason=result.json()
                    )
                except JSONDecodeError:
                    raise KeycloakError(
                        status_code=result.status_code,
                        reason=result.content.decode("utf-8"),
                    )

        return wrapper

    return inner


class FastAPIKeycloak:
    """Instance to wrap the Keycloak API with FastAPI

    Example:
        ```python
        app = FastAPI()
        idp = KeycloakFastAPI(
            server_url="https://auth.some-domain.com/auth",
            client_id="some-test-client",
            client_secret="some-secret",
            realm="Test",
            callback_uri=f"http://localhost:8081/callback"
        )
        idp.add_swagger_config(app)
        ```
    """

    def __init__(
        self,
        server_url: str,
        client_id: str,
        client_secret: str,
        realm: str,
        callback_uri: str,
        timeout: int = 10,
    ):
        """FastAPIKeycloak constructor

        Args:
            server_url (str): The URL of the Keycloak server, with `/auth` suffix
            client_id (str): The id of the client used for users
            client_secret (str): The client secret
            realm (str): The realm (name)
            callback_uri (str): Callback URL of the instance, used for auth flows. Must match at least one
            `Valid Redirect URIs` of Keycloak and should point to an endpoint that utilizes the authorization_code flow.
            timeout (int): Timeout in seconds to wait for the server
        """
        self.server_url = server_url
        self.realm = realm
        self.client_id = client_id
        self.client_secret = client_secret
        self.callback_uri = callback_uri
        self.timeout = timeout

    def add_swagger_config(self, app: FastAPI):
        """Adds the client id and secret securely to the swagger ui.
        Enabling Swagger ui users to perform actions they usually need the client credentials, without exposing them.

        Args:
            app (FastAPI): Optional FastAPI app to add the config to swagger

        Returns:
            None: Inplace method
        """
        app.swagger_ui_init_oauth = {
            "usePkceWithAuthorizationCodeGrant": True,
            "clientId": self.client_id,
            "clientSecret": self.client_secret,
        }

    @functools.cached_property
    def user_auth_scheme(self) -> OAuth2PasswordBearer:
        """Returns the auth scheme to register the endpoints with swagger

        Returns:
            OAuth2PasswordBearer: Auth scheme for swagger
        """
        return OAuth2PasswordBearer(tokenUrl=self.token_uri)

    def get_current_user(
        self, required_roles: List[str] = None, extra_fields: List[str] = None
    ) -> Callable:
        """Returns the current user based on an access token in the HTTP-header. Optionally verifies roles are possessed
        by the user

        Args:
            required_roles List[str]: List of role names required for this endpoint
            extra_fields List[str]: The names of the additional fields you need that are encoded in JWT

        Returns:
            Callable[OAuth2PasswordBearer, OIDCUser]: Dependency method which returns the decoded JWT content

        Raises:
            ExpiredSignatureError: If the token is expired (exp > datetime.now())
            JWTError: If decoding fails or the signature is invalid
            JWTClaimsError: If any claim is invalid
            HTTPException: If any role required is not contained within the roles of the users
        """

        def current_user(
            token: OAuth2PasswordBearer = Depends(self.user_auth_scheme),
        ) -> OIDCUser:
            """Decodes and verifies a JWT to get the current user

            Args:
                token OAuth2PasswordBearer: Access token in `Authorization` HTTP-header

            Returns:
                OIDCUser: Decoded JWT content

            Raises:
                ExpiredSignatureError: If the token is expired (exp > datetime.now())
                JWTError: If decoding fails or the signature is invalid
                JWTClaimsError: If any claim is invalid
                HTTPException: If any role required is not contained within the roles of the users
            """
            try:
                decoded_token = self._decode_token(token=token, audience="account")
            except JWTError as err:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=str(err),
                )
            user = OIDCUser.parse_obj(decoded_token)
            if required_roles:
                for role in required_roles:
                    if role not in user.roles:
                        raise HTTPException(
                            status_code=status.HTTP_403_FORBIDDEN,
                            detail=f'Role "{role}" is required to perform this action',
                        )

            if extra_fields:
                for field in extra_fields:
                    user.extra_fields[field] = decoded_token.get(field, None)

            return user

        return current_user

    @functools.cached_property
    def open_id_configuration(self) -> dict:
        """Returns Keycloaks Open ID Connect configuration

        Returns:
            dict: Open ID Configuration
        """
        response = requests.get(
            url=f"{self.realm_uri}/.well-known/openid-configuration",
            timeout=self.timeout,
        )
        return response.json()

    @functools.cached_property
    def public_key(self) -> str:
        """Returns the Keycloak public key

        Returns:
            str: Public key for JWT decoding
        """
        response = requests.get(url=self.realm_uri, timeout=self.timeout)
        public_key = response.json()["public_key"]
        return f"-----BEGIN PUBLIC KEY-----\n{public_key}\n-----END PUBLIC KEY-----"

    @result_or_error(response_model=KeycloakToken)
    def user_login(self, username: str, password: str) -> KeycloakToken:
        """Models the password OAuth2 flow. Exchanges username and password for an access token. Will raise detailed
        errors if login fails due to requiredActions

        Args:
            username (str): Username used for login
            password (str): Password of the user

        Returns:
            KeycloakToken: If the exchange succeeds

        Raises:
            HTTPException: If the credentials did not match any user
            MandatoryActionException: If the login is not possible due to mandatory actions
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299, != 400, != 401)

        Notes:
            - To avoid calling this multiple times, you may want to check all requiredActions of the user if it fails
            due to a (sub)instance of an MandatoryActionException
        """
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "username": username,
            "password": password,
            "grant_type": "password",
        }
        response = requests.post(
            url=self.token_uri, headers=headers, data=data, timeout=self.timeout
        )
        if response.status_code == 401:
            raise HTTPException(status_code=401, detail="Invalid user credentials")
        return KeycloakToken(**json.loads(response.content))

    @result_or_error(response_model=KeycloakToken)
    def exchange_authorization_code(
        self, session_state: str, code: str
    ) -> KeycloakToken:
        """Models the authorization code OAuth2 flow. Opening the URL provided by `login_uri` will result in a
        callback to the configured callback URL. The callback will also create a session_state and code query
        parameter that can be exchanged for an access token.

        Args:
            session_state (str): Salt to reduce the risk of successful attacks
            code (str): The authorization code

        Returns:
            KeycloakToken: If the exchange succeeds

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        """
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "code": code,
            "session_state": session_state,
            "grant_type": "authorization_code",
            "redirect_uri": self.callback_uri,
        }
        response = requests.post(
            url=self.token_uri,
            headers=headers,
            data=data,
            timeout=self.timeout,
        )
        return KeycloakToken(**json.loads(response.content))

    @functools.cached_property
    def login_uri(self):
        """The URL for users to login on the realm. Also adds the client id and the callback."""
        params = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": self.callback_uri,
        }
        return f"{self.authorization_uri}?{urlencode(params)}"

    @functools.cached_property
    def authorization_uri(self):
        """The authorization endpoint URL"""
        return self.open_id_configuration.get("authorization_endpoint")

    @functools.cached_property
    def token_uri(self):
        """The token endpoint URL"""
        return self.open_id_configuration.get("token_endpoint")

    @functools.cached_property
    def logout_uri(self):
        """The logout endpoint URL"""
        return self.open_id_configuration.get("end_session_endpoint")

    @functools.cached_property
    def realm_uri(self):
        """The realm's endpoint URL"""
        return f"{self.server_url}/realms/{self.realm}"

    @functools.cached_property
    def _open_id(self):
        """The base endpoint for any opendid connect config info"""
        return f"{self.realm_uri}/protocol/openid-connect"

    def open_id(self, resource: str):
        """Returns a openip connect resource URL"""
        return f"{self._open_id}/{resource}"

    def token_is_valid(self, token: str, audience: str = None) -> bool:
        """Validates an access token, optionally also its audience

        Args:
            token (str): The token to be verified
            audience (str): Optional audience. Will be checked if provided

        Returns:
            bool: True if the token is valid
        """
        try:
            self._decode_token(token=token, audience=audience)
            return True
        except (ExpiredSignatureError, JWTError, JWTClaimsError):
            return False

    def _decode_token(
        self, token: str, options: dict = None, audience: str = None
    ) -> dict:
        """Decodes a token, verifies the signature by using Keycloaks public key. Optionally verifying the audience

        Args:
            token (str):
            options (dict):
            audience (str): Name of the audience, must match the audience given in the token

        Returns:
            dict: Decoded JWT

        Raises:
            ExpiredSignatureError: If the token is expired (exp > datetime.now())
            JWTError: If decoding fails or the signature is invalid
            JWTClaimsError: If any claim is invalid
        """
        if options is None:
            options = {
                "verify_signature": True,
                "verify_aud": audience is not None,
                "verify_exp": True,
            }
        return jwt.decode(
            token=token,
            key=self.public_key,
            options=options,
            audience=audience,
        )

    def __str__(self):
        """String representation"""
        return "FastAPI Keycloak Integration"

    def __repr__(self):
        """Debug representation"""
        return f"{self.__str__()} <class {self.__class__} >"
