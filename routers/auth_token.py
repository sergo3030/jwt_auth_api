import hashlib
import hmac
import secrets
import time
from datetime import datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, Response, Cookie, Header
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
jwt_conf = config["jwt"]
csrf_conf = config["csrf"]

router = APIRouter(prefix="/token", tags=["token"])
mysql_connector = RDBConnection()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
logger = utils.initiate_logger(__name__)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token/create",
                                     scopes=jwt_conf["scopes"])


class JWTConstructor:
    _algorithm = jwt_conf["algorithm"]
    __secret_key = jwt_conf["secret_key"]

    def __init__(self, session_id: str, user_data: UserAllData):
        self.jwt_id = secrets.token_hex(16)
        self.session_id = session_id
        self.user_data = user_data
        self.current_time = datetime.now()

    def construct_access_token(self, access_token_expiry):
        access_token_claims = {
            "jti": self.jwt_id,
            "sid": self.session_id,
            "aud": self.user_data.id,
            "sub": self.user_data.username,
            "scopes": [self.user_data.permissions],
            "iat": datetime.now(),
            "exp": self._set_expiry_date(token_type="Access",
                                         expiry_time=access_token_expiry)
        }
        access_token = jwt.encode(claims=access_token_claims,
                                  key=self.__secret_key,
                                  algorithm=self._algorithm)
        return access_token

    def construct_refresh_token(self, refresh_token_expiry):
        refresh_token_claims = {
            "jti": self.jwt_id,
            "sid": self.session_id,
            "aud": self.user_data.id,
            "sub": self.user_data.username,
            "exp": self._set_expiry_date(token_type="Refresh",
                                         expiry_time=refresh_token_expiry)
        }
        refresh_token = jwt.encode(claims=refresh_token_claims,
                                   key=self.__secret_key,
                                   algorithm=self._algorithm)
        return refresh_token

    def _set_expiry_date(self, token_type: str, expiry_time: int) -> datetime:
        jwt_expiry_delta = timedelta(seconds=expiry_time)
        expiry_date = self.current_time + jwt_expiry_delta
        logger.info(msg=f"{self.user_data.username} issued {token_type} token; "
                        f"creation local time: {self.current_time}, expiry local time: {expiry_date}")
        return expiry_date


def construct_csrf_token(session_id):
    csrf_token_id = secrets.token_hex(16)
    plain_payload = f"{session_id}!{csrf_token_id}"
    hashed_payload = get_hashed_payload(payload=plain_payload,
                                        secret_key=csrf_conf["secret_key"])
    csrf_token = f"{hashed_payload}.{plain_payload}"
    return csrf_token


class CSRFTokenValidator:
    __secret_key = csrf_conf["secret_key"]

    def __init__(self, csrf_token_header, csrf_token_cookie):
        self.csrf_token_header = csrf_token_header
        self.csrf_token_cookie = csrf_token_cookie

    def verify_header(self):
        if self.csrf_token_header != self.csrf_token_cookie:
            logger.error(msg=f"CSRF token from header does not match token from cookie")
            raise exceptions["csrf_token"]

    def validate_signature(self):
        split_token = self.csrf_token_cookie.split(".")
        hashed_payload = split_token[0]
        plain_payload = split_token[1]
        hashed_unverified_payload = get_hashed_payload(plain_payload, secret_key=self.__secret_key)
        signature_match = hmac.compare_digest(hashed_payload, hashed_unverified_payload)
        if not signature_match:
            logger.error(msg=f"CSRF token signature validation result: FAILED")
            raise exceptions["csrf_token"]


def initiate_csrf_validation(x_csrf_token: Annotated[str, Header()],
                             csrf_token: str = Cookie()):
    csrf_validator = CSRFTokenValidator(csrf_token_header=x_csrf_token,
                                        csrf_token_cookie=csrf_token)
    csrf_validator.verify_header()
    csrf_validator.validate_signature()
    logger.info(msg="CSRF validation: PASSED")


def decode_token(encoded_token):
    try:
        decoded_token = jwt.decode(token=encoded_token,
                                   key=jwt_conf["secret_key"],
                                   algorithms=jwt_conf["algorithm"],
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
    access_token = decode_token(encoded_token=access_token)
    try:
        access_token_data = AccessTokenData(token_id=access_token.get("jti"),
                                            session_id=access_token.get("sid"),
                                            user_id=access_token.get("aud"),
                                            username=access_token.get("sub"),
                                            expiry=access_token.get("exp"),
                                            timestamp=access_token.get("iat"),
                                            scopes=access_token.get("scopes"))
        verify_granted_permissions(token_data=access_token_data, granted_scopes=security_scopes.scopes)
        return access_token_data
    except error_wrappers.ValidationError as error:
        logger.error(msg=f"Invalid field is present: \n {error}")
        raise exceptions["credentials_exception"]


async def retrieve_refresh_token_data(refresh_token: str = Cookie()) -> RefreshTokenData:
    refresh_token = decode_token(encoded_token=refresh_token)
    try:
        refresh_token_data = RefreshTokenData(token_id=refresh_token.get("jti"),
                                              session_id=refresh_token.get("sid"),
                                              user_id=refresh_token.get("aud"),
                                              username=refresh_token.get("sub"),
                                              expiry=refresh_token.get("exp"))
        return refresh_token_data
    except error_wrappers.ValidationError as error:
        logger.error(msg=f"Invalid field is present: \n {error}")
        raise exceptions["credentials_exception"]


def verify_granted_permissions(token_data, granted_scopes):
    for scope in token_data.scopes:
        if scope not in granted_scopes:
            logger.error(msg=f"User {token_data.username} has {token_data.scopes} permissions, "
                             f"user needs these permissions: {granted_scopes}")
            raise exceptions["scopes_exception"]


def get_remaining_tokens_lifetimes(refresh_token_data):
    access_token_lifetime = jwt_conf["access_token_expiry_seconds"]
    refresh_token_expiry = int(refresh_token_data.expiry)
    current_time = time.time()
    refresh_token_lifetime = int(refresh_token_expiry - current_time)
    if refresh_token_lifetime < access_token_lifetime:
        logger.info(msg=f"Last token ({refresh_token_data.token_id}) rotation for {refresh_token_data.username}")
        access_token_lifetime = refresh_token_lifetime
    return access_token_lifetime, refresh_token_lifetime


def get_hashed_payload(payload: str, secret_key: str) -> str:
    encoded_secret_key = bytes(secret_key, "utf-8")
    encoded_payload = bytes(payload, "utf-8")
    csrf_hash = hmac.new(key=encoded_secret_key,
                         msg=encoded_payload,
                         digestmod=hashlib.sha256)
    hashed_payload = csrf_hash.hexdigest()
    return hashed_payload


def verify_user(form_urlencoded_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    user_data = mysql_connector.get_user_details(alias=form_urlencoded_data.username)
    compare_passwords(username=user_data.username,
                      plain_password=form_urlencoded_data.password,
                      hashed_password=user_data.hashed_password)
    return user_data


def compare_passwords(username, plain_password: str, hashed_password: str):
    passwords_match = pwd_context.verify(plain_password, hashed_password)
    if not passwords_match:
        logger.error(msg=f"User {username} provided wrong password")
        raise exceptions["login_exception"]


def create_jwt_tokens(session_id, user_data, access_token_expiry, refresh_token_expiry):
    token_constructor = JWTConstructor(session_id, user_data)
    access_token = token_constructor.construct_access_token(access_token_expiry)
    refresh_token = token_constructor.construct_refresh_token(refresh_token_expiry)
    return access_token, refresh_token


@router.post("/create")
async def login(response: Response, user_data: Annotated[UserAllData, Depends(verify_user)]):
    logger.info(msg=f"{user_data.username} performed login request")
    session_id = secrets.token_hex(16)
    access_token, refresh_token = create_jwt_tokens(session_id, user_data,
                                                    access_token_expiry=jwt_conf["access_token_expiry_seconds"],
                                                    refresh_token_expiry=jwt_conf["refresh_token_expiry_seconds"])
    csrf_token = construct_csrf_token(session_id)
    response.set_cookie(key="access_token", value=f"{access_token}", httponly=True, secure=False)
    response.set_cookie(key="refresh_token", value=f"{refresh_token}", httponly=True, secure=False,
                        path="/token/refresh")
    response.set_cookie(key="csrf_token", value=f"{csrf_token}", httponly=False, secure=False)

    logger.info(msg=f"Token pair for {user_data.username} was created successfully")
    return {"username": f"{user_data.username}",
            "message": "Token pair was created successfully.",
            "timestamp": f"{datetime.now()}"}


@router.post("/refresh", dependencies=[Depends(initiate_csrf_validation)])
async def refresh_token_pair(response: Response,
                             refresh_token_data: Annotated[RefreshTokenData, Depends(retrieve_refresh_token_data)]):
    logger.info(msg=f"{refresh_token_data.username} requested token pair refresh")
    user_data = mysql_connector.get_user_details(alias=refresh_token_data.username)
    access_token_expiry, refresh_token_expiry = get_remaining_tokens_lifetimes(refresh_token_data)

    session_id = refresh_token_data.session_id
    access_token, refresh_token = create_jwt_tokens(session_id, user_data, access_token_expiry, refresh_token_expiry)
    response.set_cookie(key="access_token", value=f"{access_token}", httponly=True, secure=False)
    response.set_cookie(key="refresh_token", value=f"{refresh_token}", httponly=True, secure=False,
                        path="/token/refresh")

    logger.info(msg=f"Token pair for {refresh_token_data.username} was refreshed successfully")
    return {"username": f"{user_data.username}",
            "message": "Token pair was refreshed successfully.",
            "timestamp": f"{datetime.now()}"}
