import datetime
from pydantic import BaseModel


# Token
class AccessTokenData(BaseModel):
    token_id: str
    user_id: str
    alias: str
    scopes: list[str] = []


class RefreshTokenData(BaseModel):
    token_id: str
    user_id: str
    alias: str
    expiry: str


# Users
class UserDefinedPublicData(BaseModel):
    username: str
    email: str
    full_name: str


class SystemDefinedPublicData(BaseModel):
    permissions: str
    creation_date: datetime.datetime


class SystemDefinedPrivateData(BaseModel):
    id: str
    hashed_password: str


class UserPublicData(UserDefinedPublicData,
                     SystemDefinedPublicData):
    pass


class UserAllData(UserPublicData,
                  SystemDefinedPrivateData):
    pass
