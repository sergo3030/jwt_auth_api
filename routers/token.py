import time
import uuid
from datetime import datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, Response, Cookie
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer, SecurityScopes
from jose import jwt, JWTError, ExpiredSignatureError
from passlib.context import CryptContext
from pydantic import error_wrappers

import utils
from config import config
from db_connection import RDBConnection
from routers.custom_http_exceptions import exceptions
from schemas import AccessTokenData, RefreshTokenData, UserAllData

server_conf = config["server"]
token_conf = config["jwt"]

router = APIRouter(prefix="/token", tags=["token"])
mysql_connector = RDBConnection()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
logger = utils.initiate_logger(__name__)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token",
                                     scopes=token_conf["scopes"])


class JWTConstructor:
    _algorithm = token_conf["algorithm"]
    _secret_key = token_conf["secret_key"]

    def __init__(self, user_data):
        self.user_data: UserAllData = user_data
        self.jwt_id = str(uuid.uuid4())

    def construct_access_token(self, access_token_expiry):
        access_token_claims = {
            "jti": self.jwt_id,
            "aud": self.user_data.id,
            "sub": self.user_data.username,
            "scopes": [self.user_data.permissions],
            "iat": self._get_issue_date(),
            "exp": self._set_expiry_date(token_type="Access",
                                         expiry_time=access_token_expiry)
        }
        access_token = jwt.encode(claims=access_token_claims,
                                  key=self._secret_key,
                                  algorithm=self._algorithm)
        return access_token

    def construct_refresh_token(self, refresh_token_expiry):
        refresh_token_claims = {
            "jti": self.jwt_id,
            "aud": self.user_data.id,
            "sub": self.user_data.username,
            "exp": self._set_expiry_date(token_type="Refresh",
                                         expiry_time=refresh_token_expiry)
        }
        refresh_token = jwt.encode(claims=refresh_token_claims,
                                   key=self._secret_key,
                                   algorithm=self._algorithm)
        return refresh_token

    def _set_expiry_date(self, token_type: str, expiry_time: int) -> datetime:
        jwt_expiry_delta = timedelta(seconds=expiry_time)
        expiry_date = datetime.now() + jwt_expiry_delta
        logger.info(msg=f"User: {self.user_data.username}, token type: '{token_type}', "
                        f"creation local time: {datetime.now()}, expiry local time: {expiry_date}")
        return expiry_date

    @staticmethod
    def _get_issue_date() -> datetime:
        issued_at_date = datetime.now()
        return issued_at_date


class JWTDecoder:
    _algorithm = token_conf["algorithm"]
    _secret_key = token_conf["secret_key"]

    def __init__(self, encoded_token):
        self.encoded_token = encoded_token

    def decode(self):
        try:
            decoded_token = jwt.decode(token=self.encoded_token,
                                       key=self._secret_key,
                                       algorithms=self._algorithm,
                                       options={"verify_aud": False})
            return decoded_token
        except ExpiredSignatureError:
            logger.error(msg=f"Token expiry date exceeded")
            raise exceptions["expired_signature"]
        except JWTError as error:
            logger.error(msg=f"Error occurred while validating token. {error}")
            raise exceptions["credentials_exception"]


async def retrieve_access_token_data(security_scopes: SecurityScopes,
                                     access_token: str = Cookie()) -> AccessTokenData:
    access_token = JWTDecoder(encoded_token=access_token).decode()
    try:
        access_token_data = AccessTokenData(token_id=access_token.get("jti"),
                                            user_id=access_token.get("aud"),
                                            username=access_token.get("sub"),
                                            expiry=access_token.get("exp"),
                                            timestamp=access_token.get("iat"),
                                            scopes=access_token.get("scopes"))
        verify_permissions(token_data=access_token_data, granted_scopes=security_scopes.scopes)
        return access_token_data
    except error_wrappers.ValidationError as error:
        logger.error(msg=f"Invalid field is present: \n {error}")
        raise exceptions["credentials_exception"]


async def retrieve_refresh_token_data(refresh_token: str = Cookie()) -> RefreshTokenData:
    refresh_token = JWTDecoder(encoded_token=refresh_token).decode()
    try:
        refresh_token_data = RefreshTokenData(token_id=refresh_token.get("jti"),
                                              user_id=refresh_token.get("aud"),
                                              username=refresh_token.get("sub"),
                                              expiry=refresh_token.get("exp"))
        return refresh_token_data
    except error_wrappers.ValidationError as error:
        logger.error(msg=f"Invalid field is present: \n {error}")
        raise exceptions["credentials_exception"]


def get_tokens_remaining_expiry(refresh_token_data: RefreshTokenData):
    access_token_expiry = token_conf["access_token_expiry_seconds"]
    refresh_token_expiry_epoch = float(refresh_token_data.expiry)
    current_time_epoch = time.time()

    refresh_token_expiry = int(refresh_token_expiry_epoch - current_time_epoch)
    if refresh_token_expiry < access_token_expiry:
        logger.info(msg=f"Last token pair rotation. "
                        f"User: {refresh_token_data.username}; Token family: {refresh_token_data.token_id}")
        access_token_expiry = refresh_token_expiry
        return access_token_expiry, refresh_token_expiry
    return access_token_expiry, refresh_token_expiry


def verify_permissions(token_data, granted_scopes):
    for scope in token_data.scopes:
        if scope not in granted_scopes:
            logger.error(msg=f"User {token_data.username} has {token_data.scopes} permissions, "
                             f"user needs these permissions: {granted_scopes}")
            raise exceptions["scopes_exception"]
    return True


def compare_passwords(username, plain_password: str, hashed_password: str) -> bool:
    passwords_match = pwd_context.verify(plain_password, hashed_password)
    if not passwords_match:
        logger.error(msg=f"User {username} provided wrong password")
        raise exceptions["login_exception"]
    return True


def create_token_pair(user_data,
                      access_token_expiry=token_conf["access_token_expiry_seconds"],
                      refresh_token_expiry=token_conf["refresh_token_expiry_seconds"]):
    token_constructor = JWTConstructor(user_data)
    # jti = token_constructor.jwt_id
    access_token = token_constructor.construct_access_token(access_token_expiry)
    refresh_token = token_constructor.construct_refresh_token(refresh_token_expiry)
    return access_token, refresh_token


@router.post("")
async def login_for_access(response: Response,
                           form_urlencoded_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    logger.info(msg=f"User {form_urlencoded_data.username} requested a token pair creation")
    alias = form_urlencoded_data.username
    password = form_urlencoded_data.password

    user_data = mysql_connector.get_user_details(alias)
    compare_passwords(user_data.username, password, user_data.hashed_password)

    access_token, refresh_token = create_token_pair(user_data)
    response.set_cookie(key="access_token", value=f"{access_token}",
                        httponly=True, secure=False)
    response.set_cookie(key="refresh_token", value=f"{refresh_token}",
                        httponly=True, secure=False, path="/token/refresh")

    logger.info(msg=f"Token pair for {user_data.username} was created successfully")
    return {"username": f"{user_data.username}",
            "message": "Token pair was created successfully.",
            "timestamp": f"{datetime.now()}"}


@router.post("/refresh")
async def refresh_token_pair(response: Response,
                             refresh_token_data: Annotated[RefreshTokenData, Depends(retrieve_refresh_token_data)]):
    logger.info(msg=f"User {refresh_token_data.username} requested a token pair refresh")

    user_data = mysql_connector.get_user_details(alias=refresh_token_data.username)
    access_token_expiry, refresh_token_expiry = get_tokens_remaining_expiry(refresh_token_data)

    access_token, refresh_token = create_token_pair(user_data, access_token_expiry, refresh_token_expiry)
    response.set_cookie(key="access_token", value=f"{access_token}",
                        httponly=True, secure=False)
    response.set_cookie(key="refresh_token", value=f"{refresh_token}",
                        httponly=True, secure=False, path="/token/refresh")

    logger.info(msg=f"Token pair for {refresh_token_data.username} was refreshed successfully")
    return {"username": f"{user_data.username}",
            "message": "Token pair was refreshed successfully.",
            "timestamp": f"{datetime.now()}"}
