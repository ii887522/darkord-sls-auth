import logging

import auth_constants
import auth_jwt
import auth_user
import boto3
import common
import common_db
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
    "dynamodb", constants.REGION, config=Config(tcp_keepalive=True)
)

AUTH_ATTEMPT_TABLE = DYNAMODB.Table(auth_constants.AUTH_ATTEMPT_TABLE_NAME)
SSM = boto3.client("ssm", constants.REGION, config=Config(tcp_keepalive=True))

SESSION_TOKEN_SECRET = SSM.get_parameter(
    Name=auth_constants.SESSION_TOKEN_PARAM_NAME, WithDecryption=True
)["Parameter"].get("Value", "")


class RequestSchema(BaseRequestSchema):
    username = TrimmedField(
        inner=fields.String(), required=True, validate=Length(min=1)
    )

    email_addr = fields.Email(required=True, validate=Length(min=1))
    password = fields.String(required=True, validate=Length(min=1))

    locale = TrimmedField(
        inner=fields.String(),
        validate=OneOf((auth_constants.LANG_EN,)),
        load_default=auth_constants.LANG_EN,
    )

    extra = fields.Dict(load_default={})


class ResponseSchema(BaseResponseSchema):
    session_token = fields.String()
    verification_code = fields.String()  # TODO: Only for testing purpose. To be removed


@log_event
def handler(event, context):
    try:
        if AuthAttemptDb(dynamodb=DYNAMODB, table=AUTH_ATTEMPT_TABLE).is_blocked(
            action=auth_constants.ACTION_SIGN_UP,
            ip_addr=common.get_user_ip(event=event),
        ):
            raise CommonException(code=4030)

        req = RequestSchema().load_and_dump(event)
        username = req["username"]
        email_addr = req["email_addr"]
        password, salt = common.hash_secret(secret=req["password"])
        locale = req["locale"]
        extra = req["extra"]
        verification_code = common.gen_secret_digits()
        code_expired_at = common.extend_current_timestamp(minutes=3)

        try:
            transact_items: list = [
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
                TransactItems=transact_items
            )
            LOGGER.debug("db_resp: %s", db_resp)

        except DYNAMODB.meta.client.exceptions.TransactionCanceledException as err:
            for reason in err.response["CancellationReasons"]:
                if reason["Code"] != "ConditionalCheckFailed":
                    continue

                item = common_db.deserialize_item(item=reason.get("Item", {}))

                if item.get("pk", "").startswith("Username#"):
                    raise CommonException(code=4090, msg="Username already exists")

                if item.get("pk", "").startswith("EmailAddr#"):
                    raise CommonException(code=4091, msg="Email address already exists")

        # TODO: Send a verification email to the given email address with the verification code
        # TODO: Email content based on the given locale

        # Generate a new session token that is authorized to call verify-email API
        session_token = auth_jwt.encode(
            key=SESSION_TOKEN_SECRET,
            type=auth_constants.TOKEN_TYPE_SESSION,
            exp=common.extend_current_timestamp(
                minutes=auth_constants.JWT_TOKEN_VALIDITY_IN_MINUTES_DICT[
                    auth_constants.ACTION_VERIFY_ATTR
                ]
            ),
            sub=email_addr,
            name=username,
            aud=auth_constants.ACTION_VERIFY_ATTR,
            dest=auth_constants.ACTION_INIT_MFA,
        )

        return common.gen_api_resp(
            code=2000,
            payload=ResponseSchema().load_and_dump(
                {
                    "session_token": session_token,
                    "verification_code": verification_code,  # TODO: Only for testing purpose. To be removed
                }
            ),
        )

    except CommonException as err:
        # Only increment if error message is not Forbidden, else user keep trying will never be able to sign up
        if err.code != 4030:
            AuthAttemptDb(dynamodb=DYNAMODB, table=AUTH_ATTEMPT_TABLE).incr(
                action=auth_constants.ACTION_SIGN_UP,
                ip_addr=common.get_user_ip(event=event),
            )

        return common.gen_api_resp(code=err.code, msg=err.msg)

    except Exception as err:
        LOGGER.exception(err)
        return common.gen_api_resp(code=5000)
