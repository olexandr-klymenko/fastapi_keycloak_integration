from typing import List, Optional

from pydantic import BaseModel, Field, SecretStr

from .exceptions import KeycloakError


class KeycloakUser(BaseModel):
    """Represents a user object of Keycloak.

    Attributes:
        id (str):
        createdTimestamp (int):
        username (str):
        enabled (bool):
        totp (bool):
        emailVerified (bool):
        firstName (Optional[str]):
        lastName (Optional[str]):
        email (Optional[str]):
        disableableCredentialTypes (List[str]):
        requiredActions (List[str]):
        realmRoles (List[str]):
        notBefore (int):
        access (dict):
        attributes (Optional[dict]):

    Notes: Check the Keycloak documentation at https://www.keycloak.org/docs-api/15.0/rest-api/index.html for
    details. This is a mere proxy object.
    """

    id: str
    createdTimestamp: int
    username: str
    enabled: bool
    totp: bool
    emailVerified: bool
    firstName: Optional[str]
    lastName: Optional[str]
    email: Optional[str]
    disableableCredentialTypes: List[str]
    requiredActions: List[str]
    realmRoles: Optional[List[str]]
    notBefore: int
    access: dict
    attributes: Optional[dict]


class OIDCUser(BaseModel):
    """Represents a user object of Keycloak, parsed from access token

    Attributes:
        sub (str):
        iat (int):
        exp (int):
        scope (str):
        email_verified (bool):
        name (Optional[str]):
        given_name (Optional[str]):
        family_name (Optional[str]):
        email (Optional[str]):
        preferred_username (Optional[str]):
        realm_access (dict):
        resource_access (dict):
        extra_fields (dict):

    Notes: Check the Keycloak documentation at https://www.keycloak.org/docs-api/15.0/rest-api/index.html for
    details. This is a mere proxy object.
    """

    sub: str
    iat: int
    exp: int
    scope: Optional[str]
    email_verified: bool
    name: Optional[str]
    given_name: Optional[str]
    family_name: Optional[str]
    email: Optional[str]
    preferred_username: Optional[str]
    realm_access: Optional[dict]
    resource_access: Optional[dict]
    extra_fields: dict = Field(default_factory=dict)

    @property
    def roles(self) -> List[str]:
        """Returns the roles of the user

        Returns:
            List[str]: If the realm access dict contains roles
        """
        if not self.realm_access:
            raise KeycloakError(
                status_code=404,
                reason="The 'realm_access' section of the provided access token is missing",
            )
        try:
            return self.realm_access["roles"]
        except KeyError as e:
            raise KeycloakError(
                status_code=404,
                reason="The 'realm_access' section of the provided access token did not contain any 'roles'",
            ) from e

    def __str__(self) -> str:
        """String representation of an OIDCUser"""
        return self.preferred_username


class KeycloakToken(BaseModel):
    """Keycloak representation of a token object

    Attributes:
        access_token (str): An access token
    """

    access_token: str

    def __str__(self):
        """String representation of KeycloakToken"""
        return f"Bearer {self.access_token}"


class KeycloakGroup(BaseModel):
    """Keycloak representation of a group

    Attributes:
        id (str):
        name (str):
        path (Optional[str]):
        realmRoles (Optional[str]):
    """

    id: str
    name: str
    path: Optional[str]
    realmRoles: Optional[List[str]]
    subGroups: Optional[List["KeycloakGroup"]]


KeycloakGroup.update_forward_refs()
