import logging
from typing import Literal

import auth_constants
import boto3
import common
import constants
import jmespath
import jwt
from auth_rbac import AuthRbacDb
from auth_valid_token_pair import AuthValidTokenPairDb
from botocore.config import Config
from common_decorators import log_event
from jwt.exceptions import (
    DecodeError,
    ExpiredSignatureError,
    InvalidAlgorithmError,
    InvalidSignatureError,
    InvalidTokenError,
    MissingRequiredClaimError,
)

LOGGER = logging.getLogger()

DYNAMODB = boto3.resource(
    "dynamodb", constants.REGION, config=Config(tcp_keepalive=True)
)

AUTH_VALID_TOKEN_PAIR_TABLE = DYNAMODB.Table(
    auth_constants.AUTH_VALID_TOKEN_PAIR_TABLE_NAME
)

AUTH_RBAC_TABLE = DYNAMODB.Table(auth_constants.AUTH_RBAC_TABLE_NAME)

SSM = boto3.client("ssm", constants.REGION, config=Config(tcp_keepalive=True))

ACCESS_TOKEN_SECRET, REFRESH_TOKEN_SECRET, SESSION_TOKEN_SECRET = jmespath.search(
    "[*].Value",
    SSM.get_parameters_by_path(
        Path=auth_constants.JWT_TOKEN_PARAM_PATH, Recursive=False, WithDecryption=True
    )["Parameters"],
)


@log_event
def handler(event, context):
    try:
        claims = decode(jwt_token=get_auth_token(event=event))

        if claims["typ"] == auth_constants.TOKEN_TYPE_ACCESS:
            return auth_access_token(event=event, claims=claims)

        elif claims["typ"] == auth_constants.TOKEN_TYPE_REFRESH:
            return auth_refresh_token(event=event, claims=claims)

        elif claims["typ"] == auth_constants.TOKEN_TYPE_SESSION:
            return auth_session_token(event=event, claims=claims)

    except (
        MissingRequiredClaimError,
        InvalidAlgorithmError,
        ExpiredSignatureError,
        InvalidSignatureError,
        DecodeError,
        InvalidTokenError,
    ) as err:
        LOGGER.exception(err)
        raise Exception("Unauthorized")

    except Exception as err:
        LOGGER.exception(err)
        return "unauthorized"


def get_auth_token(event) -> str:
    if event["type"] == "TOKEN":
        return event.get("authorizationToken", "")

    elif event["type"] == "REQUEST":
        return event["headers"].get("Authorization", "")

    return ""


def decode(jwt_token: str) -> dict:
    # Find the type of this auth token
    claims = jwt.decode(jwt=jwt_token, options={"verify_signature": False})
    key = ""

    if claims["typ"] == auth_constants.TOKEN_TYPE_ACCESS:
        key = ACCESS_TOKEN_SECRET

    elif claims["typ"] == auth_constants.TOKEN_TYPE_REFRESH:
        key = REFRESH_TOKEN_SECRET

    elif claims["typ"] == auth_constants.TOKEN_TYPE_SESSION:
        key = SESSION_TOKEN_SECRET

    # Ensure the given JWT token is valid
    jwt.decode(
        jwt=jwt_token,
        key=key,
        algorithms=["HS512"],
        options={"require": ["exp"]},
        audience=auth_constants.AUDIENCE_ACTIONS,
    )

    return claims


def gen_policy(
    event,
    principal_id: str,
    effect: Literal["Allow", "Deny"],
    jti: str,
    sub="",
    name="",
    dest="",
) -> dict:
    return {
        "principalId": principal_id,
        "policyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": "execute-api:Invoke",
                    "Effect": effect,
                    "Resource": event["methodArn"],
                }
            ],
        },
        "context": {"jti": jti, "sub": sub, "name": name, "dest": dest},
    }


def auth_access_token(event, claims: dict) -> dict:
    refresh_token_jti = claims["orig"]
    access_token_jti = claims["jti"]
    email_addr = claims["sub"]
    username = claims["name"]

    valid_token_pair = AuthValidTokenPairDb(table=AUTH_VALID_TOKEN_PAIR_TABLE).get(
        refresh_token_jti=refresh_token_jti
    )

    if not valid_token_pair or access_token_jti != valid_token_pair["access_token_jti"]:
        raise Exception("Unauthorized")

    method_arn_dict = common.deserialize_method_arn(method_arn=event["methodArn"])

    rbac = AuthRbacDb(table=AUTH_RBAC_TABLE).get(
        method=method_arn_dict["method"], path=method_arn_dict["path"]
    )

    if not rbac or set(claims["roles"]).isdisjoint(rbac["roles"]):
        return gen_policy(
            event=event,
            principal_id=username,
            effect="Deny",
            jti=access_token_jti,
            sub=email_addr,
            name=username,
        )

    return gen_policy(
        event=event,
        principal_id=username,
        effect="Allow",
        jti=access_token_jti,
        sub=email_addr,
        name=username,
    )


def auth_refresh_token(event, claims: dict) -> dict:
    refresh_token_jti = claims["jti"]

    valid_token_pair = AuthValidTokenPairDb(table=AUTH_VALID_TOKEN_PAIR_TABLE).get(
        refresh_token_jti=refresh_token_jti
    )

    if not valid_token_pair:
        raise Exception("Unauthorized")

    method_arn_dict = common.deserialize_method_arn(method_arn=event["methodArn"])

    if not method_arn_dict["path"].endswith("/refresh"):
        return gen_policy(
            event=event,
            principal_id=refresh_token_jti,
            effect="Deny",
            jti=refresh_token_jti,
        )

    return gen_policy(
        event=event,
        principal_id=refresh_token_jti,
        effect="Allow",
        jti=refresh_token_jti,
    )


def auth_session_token(event, claims: dict) -> dict:
    aud = claims["aud"]
    email_addr = claims["sub"]
    username = claims["name"]
    jti = claims["jti"]
    dest = claims["dest"]
    method_arn_dict = common.deserialize_method_arn(method_arn=event["methodArn"])

    if not method_arn_dict["path"].endswith(f"/{aud}"):
        return gen_policy(
            event=event,
            principal_id=username,
            effect="Deny",
            jti=jti,
            sub=email_addr,
            name=username,
            dest=dest,
        )

    return gen_policy(
        event=event,
        principal_id=username,
        effect="Allow",
        jti=jti,
        sub=email_addr,
        name=username,
        dest=dest,
    )
