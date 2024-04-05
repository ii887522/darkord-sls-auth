import logging

import auth_attempt
import auth_constants
import auth_user
import boto3
import common
import constants
from auth_attempt import AuthAttemptDb
from botocore.config import Config
from common_decorators import log_event
from common_exception import CommonException
from common_marshmallow import BaseRequestSchema, BaseResponseSchema, TrimmedField
from marshmallow import fields
from marshmallow.validate import Length, OneOf

LOGGER = logging.getLogger()

DYNAMODB = boto3.resource(
    "dynamodb",
    constants.REGION,
    config=Config(tcp_keepalive=True),
)

AUTH_ATTEMPT_TABLE = DYNAMODB.Table(auth_constants.AUTH_ATTEMPT_TABLE_NAME)


class RequestSchema(BaseRequestSchema):
    username = TrimmedField(
        inner=fields.String(),
        required=True,
        validate=Length(min=1),
    )

    email_addr = fields.Email(required=True, validate=Length(min=1))
    password = fields.String(required=True, validate=Length(min=1))

    locale = fields.String(
        validate=OneOf((auth_constants.LANG_EN,)),
        load_default=auth_constants.LANG_EN,
    )

    extra = fields.Dict(load_default={})


class ResponseSchema(BaseResponseSchema):
    session_token = fields.String()


@log_event
def handler(event, context):
    user_ip = event["requestContext"]["identity"]["sourceIp"]

    try:
        req = RequestSchema().load_and_dump(event)
        username = req["username"]
        email_addr = req["email_addr"]
        password, salt = common.hash_secret(req["password"])
        locale = req["locale"]
        extra = req["extra"]
        verification_code = common.gen_secret_digits()
        code_expired_at = common.extend_current_timestamp(minutes=3)

        try:
            transact_items: list = [
                auth_attempt.get_cond_check_transact_item(
                    action=auth_constants.ACTION_SIGN_UP,
                    ip_addr=user_ip,
                    max_attempt=auth_constants.MAX_SIGN_UP_ATTEMPT,
                ),
                auth_user.get_put_transact_item(
                    username=username,
                    email_addr=email_addr,
                    password=password,
                    salt=salt,
                    locale=locale,
                    extra=extra,
                ),
                auth_user.get_put_transact_item(
                    username=username,
                    email_addr=email_addr,
                    verification_code=verification_code,
                    code_expired_at=code_expired_at,
                ),
            ]

            db_resp = DYNAMODB.meta.client.transact_write_items(
                TransactItems=transact_items,
            )
            LOGGER.debug("db_resp: %s", db_resp)

        except DYNAMODB.meta.client.exceptions.ConditionalCheckFailedException as err:
            item = err.response.get("Item", {})

            if item.get("attempt", 0) >= auth_constants.MAX_SIGN_UP_ATTEMPT:
                raise CommonException(code=4030)

            if item.get("pk", "").startswith("Username#"):
                raise CommonException(code=4090, msg="Username already exists")

            if item.get("pk", "").startswith("EmailAddr#"):
                raise CommonException(code=4091, msg="Email address already exists")

        # TODO: Generate a new session token that is authorized to call verify-email API. This token is only valid for 3 minutes

        return common.gen_api_resp(code=2000)

    except CommonException as err:
        AuthAttemptDb(dynamodb=DYNAMODB, table=AUTH_ATTEMPT_TABLE).incr(
            action=auth_constants.ACTION_SIGN_UP,
            ip_addr=user_ip,
        )

        return common.gen_api_resp(code=err.code, msg=err.msg)

    except Exception as err:
        LOGGER.exception(err)
        return common.gen_api_resp(code=5000)
