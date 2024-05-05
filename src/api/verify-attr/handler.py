import logging

import auth_constants
import auth_jwt
import boto3
import common
import constants
from auth_attempt import AuthAttemptDb
from auth_user import AuthUserDb
from botocore.config import Config
from common_decorators import log_event
from common_exception import CommonException
from common_marshmallow import BaseRequestSchema, BaseResponseSchema, TrimmedField
from marshmallow import fields
from marshmallow.validate import Length, OneOf

LOGGER = logging.getLogger()

DYNAMODB = boto3.resource(
    "dynamodb", constants.REGION, config=Config(tcp_keepalive=True)
)

AUTH_ATTEMPT_TABLE = DYNAMODB.Table(auth_constants.AUTH_ATTEMPT_TABLE_NAME)
AUTH_USER_TABLE = DYNAMODB.Table(auth_constants.AUTH_USER_TABLE_NAME)

SSM = boto3.client("ssm", constants.REGION, config=Config(tcp_keepalive=True))

SESSION_TOKEN_SECRET = SSM.get_parameter(
    Name=auth_constants.SESSION_TOKEN_PARAM_PATH, WithDecryption=True
)["Parameter"].get("Value", "")


class RequestSchema(BaseRequestSchema):
    attr = TrimmedField(
        inner=fields.String(), required=True, validate=OneOf(("email_addr",))
    )

    code = fields.String(required=True, validate=Length(min=1))


class ResponseSchema(BaseResponseSchema):
    session_token = fields.String()


@log_event
def handler(event, context):
    user_ctx = common.get_user_ctx(event=event)
    jti = user_ctx["jti"]

    try:
        email_addr = user_ctx["sub"]
        username = user_ctx["name"]
        next_action = user_ctx["dest"]
        attempt_db = AuthAttemptDb(dynamodb=DYNAMODB, table=AUTH_ATTEMPT_TABLE)

        if attempt_db.is_blocked(action=auth_constants.ACTION_VERIFY_ATTR, jti=jti):
            raise CommonException(code=4030)

        req = RequestSchema().load_and_dump(event)
        user_db = AuthUserDb(table=AUTH_USER_TABLE)
        verification_code = user_db.get_verification_code(email_addr=email_addr)

        if req["code"] != verification_code:
            raise CommonException(code=4001, msg="Invalid code")

        user_db.mark_attrs_as_verified(username=username, attrs={"email_addr"})

        # Revoke this session token
        attempt_db.block(action=auth_constants.ACTION_VERIFY_ATTR, jti=jti)

        # Generate a new session token that is authorized to call init-mfa / reset-password / etc. API
        session_token = auth_jwt.encode(
            key=SESSION_TOKEN_SECRET,
            type=auth_constants.TOKEN_TYPE_SESSION,
            exp=common.extend_current_timestamp(
                minutes=auth_constants.JWT_TOKEN_VALIDITY_IN_MINUTES_DICT[next_action]
            ),
            sub=email_addr,
            name=username,
            aud=next_action,
            dest=next_action,
        )

        return common.gen_api_resp(
            code=2000,
            payload=ResponseSchema().load_and_dump({"session_token": session_token}),
        )

    except CommonException as err:
        # Only increment if error message is not Forbidden, else user keep trying will never be able to verify their
        # attribute
        if err.code != 4030:
            AuthAttemptDb(dynamodb=DYNAMODB, table=AUTH_ATTEMPT_TABLE).incr(
                action=auth_constants.ACTION_VERIFY_ATTR, jti=jti
            )

        return common.gen_api_resp(code=err.code, msg=err.msg)

    except Exception as err:
        LOGGER.exception(err)
        return common.gen_api_resp(code=5000)
