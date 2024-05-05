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
from common_marshmallow import BaseRequestSchema, BaseResponseSchema
from marshmallow import fields
from marshmallow.validate import Length

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
    email_addr = fields.Email(required=True, validate=Length(min=1))
    password = fields.String(required=True, validate=Length(min=1))


class ResponseSchema(BaseResponseSchema):
    session_token = fields.String()


@log_event
def handler(event, context):
    try:
        if AuthAttemptDb(dynamodb=DYNAMODB, table=AUTH_ATTEMPT_TABLE).is_blocked(
            action=auth_constants.ACTION_LOGIN, ip_addr=common.get_user_ip(event=event)
        ):
            raise CommonException(code=4030)

        req = RequestSchema().load_and_dump(event)
        email_addr = req["email_addr"]

        user = AuthUserDb(table=AUTH_USER_TABLE).get(email_addr=email_addr)

        if not user or "email_addr" not in user.get("verified_attrs", set()):
            raise CommonException(code=4010)

        password, _ = common.hash_secret(
            secret=req["password"], salt=bytes.fromhex(user["salt"])
        )

        if password != user["password"]:
            raise CommonException(code=4010)

        username = user["username"]

        # Generate a new session JWT token that is authorized to call verify-mfa-code API
        session_token = auth_jwt.encode(
            key=SESSION_TOKEN_SECRET,
            type=auth_constants.TOKEN_TYPE_SESSION,
            exp=common.extend_current_timestamp(
                minutes=auth_constants.JWT_TOKEN_VALIDITY_IN_MINUTES_DICT[
                    auth_constants.ACTION_VERIFY_MFA_CODE
                ]
            ),
            sub=email_addr,
            name=username,
            aud=auth_constants.ACTION_VERIFY_MFA_CODE,
            dest=auth_constants.ACTION_VERIFY_MFA_CODE,
        )

        return common.gen_api_resp(
            code=2000,
            payload=ResponseSchema().load_and_dump({"session_token": session_token}),
        )

    except CommonException as err:
        # Only increment if error message is not Forbidden, else user keep trying will never be able to login
        if err.code != 4030:
            AuthAttemptDb(dynamodb=DYNAMODB, table=AUTH_ATTEMPT_TABLE).incr(
                action=auth_constants.ACTION_LOGIN,
                ip_addr=common.get_user_ip(event=event),
            )

        return common.gen_api_resp(code=err.code, msg=err.msg)

    except Exception as err:
        LOGGER.exception(err)
        return common.gen_api_resp(code=5000)
