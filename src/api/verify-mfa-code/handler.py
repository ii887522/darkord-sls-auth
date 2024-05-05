import logging
import uuid

import auth_constants
import auth_jwt
import boto3
import common
import constants
import jmespath
from auth_attempt import AuthAttemptDb
from auth_user import AuthUserDb
from auth_valid_token_pair import AuthValidTokenPairDb
from botocore.config import Config
from common_decorators import log_event
from common_exception import CommonException
from common_marshmallow import BaseRequestSchema, BaseResponseSchema
from marshmallow import fields
from marshmallow.validate import Length
from pyotp import TOTP

LOGGER = logging.getLogger()

DYNAMODB = boto3.resource(
    "dynamodb", constants.REGION, config=Config(tcp_keepalive=True)
)

AUTH_ATTEMPT_TABLE = DYNAMODB.Table(auth_constants.AUTH_ATTEMPT_TABLE_NAME)
AUTH_USER_TABLE = DYNAMODB.Table(auth_constants.AUTH_USER_TABLE_NAME)
AUTH_VALID_TOKEN_PAIR_TABLE = DYNAMODB.Table(
    auth_constants.AUTH_VALID_TOKEN_PAIR_TABLE_NAME
)

SSM = boto3.client("ssm", constants.REGION, config=Config(tcp_keepalive=True))

ACCESS_TOKEN_SECRET, REFRESH_TOKEN_SECRET, SESSION_TOKEN_SECRET = jmespath.search(
    "[*].Value",
    SSM.get_parameters_by_path(
        Path=auth_constants.JWT_TOKEN_PARAM_PATH, Recursive=False, WithDecryption=True
    )["Parameters"],
)


class RequestSchema(BaseRequestSchema):
    code = fields.String(required=True, validate=Length(min=1))


class ResponseSchema(BaseResponseSchema):
    refresh_token = fields.String()
    access_token = fields.String()


@log_event
def handler(event, context):
    user_ctx = common.get_user_ctx(event=event)
    jti = user_ctx["jti"]

    try:
        username = user_ctx["name"]
        email_addr = user_ctx["sub"]

        attempt_db = AuthAttemptDb(dynamodb=DYNAMODB, table=AUTH_ATTEMPT_TABLE)

        if attempt_db.is_blocked(action=auth_constants.ACTION_VERIFY_MFA_CODE, jti=jti):
            raise CommonException(code=4030)

        req = RequestSchema().load_and_dump(event)

        mfa_secret = AuthUserDb(table=AUTH_USER_TABLE, ssm=SSM).get_mfa_secret(
            username=username
        )

        if not mfa_secret or TOTP(mfa_secret).verify(req["code"]):
            raise CommonException(code=4010)

        # Revoke this session token
        attempt_db.block(action=auth_constants.ACTION_VERIFY_MFA_CODE, jti=jti)

        refresh_token_jti = str(uuid.uuid4())
        refresh_token_exp = common.extend_current_timestamp(days=1)

        refresh_token = auth_jwt.encode(
            key=REFRESH_TOKEN_SECRET,
            type=auth_constants.TOKEN_TYPE_REFRESH,
            exp=refresh_token_exp,
            id=refresh_token_jti,
        )

        access_token_jti = str(uuid.uuid4())

        access_token = auth_jwt.encode(
            key=ACCESS_TOKEN_SECRET,
            type=auth_constants.TOKEN_TYPE_ACCESS,
            exp=common.extend_current_timestamp(minutes=5),
            id=access_token_jti,
            sub=email_addr,
            name=username,
            roles=[auth_constants.ROLE_USER],
            orig=refresh_token_jti,
        )

        AuthValidTokenPairDb(table=AUTH_VALID_TOKEN_PAIR_TABLE).put(
            refresh_token_jti=refresh_token_jti,
            access_token_jti=access_token_jti,
            expired_at=refresh_token_exp,
        )

        return common.gen_api_resp(
            code=2000,
            payload=ResponseSchema().load_and_dump(
                {"refresh_token": refresh_token, "access_token": access_token}
            ),
        )

    except CommonException as err:
        # Only increment if error message is not Forbidden, else user keep trying will never be able to verify their
        # MFA code
        if err.code != 4030:
            AuthAttemptDb(dynamodb=DYNAMODB, table=AUTH_ATTEMPT_TABLE).incr(
                action=auth_constants.ACTION_VERIFY_MFA_CODE, jti=jti
            )

        return common.gen_api_resp(code=err.code, msg=err.msg)

    except Exception as err:
        LOGGER.exception(err)
        return common.gen_api_resp(code=5000)
