import logging

import auth_constants
import boto3
import common
import constants
import pyotp
from auth_attempt import AuthAttemptDb
from auth_user import AuthUserDb
from botocore.config import Config
from common_decorators import log_event
from common_exception import CommonException
from common_marshmallow import BaseResponseSchema
from marshmallow import fields
from pyotp import TOTP

LOGGER = logging.getLogger()

DYNAMODB = boto3.resource(
    "dynamodb", constants.REGION, config=Config(tcp_keepalive=True)
)

AUTH_ATTEMPT_TABLE = DYNAMODB.Table(auth_constants.AUTH_ATTEMPT_TABLE_NAME)
AUTH_USER_TABLE = DYNAMODB.Table(auth_constants.AUTH_USER_TABLE_NAME)

SSM = boto3.client("ssm", constants.REGION, config=Config(tcp_keepalive=True))


class ResponseSchema(BaseResponseSchema):
    mfa_provisioning_uri = fields.String()


@log_event
def handler(event, context):
    user_ctx = common.get_user_ctx(event=event)
    jti = user_ctx["jti"]

    try:
        username = user_ctx["name"]
        email_addr = user_ctx["sub"]

        attempt_db = AuthAttemptDb(dynamodb=DYNAMODB, table=AUTH_ATTEMPT_TABLE)

        if attempt_db.is_blocked(action=auth_constants.ACTION_INIT_MFA, jti=jti):
            raise CommonException(code=4030)

        # Revoke this session token
        attempt_db.block(action=auth_constants.ACTION_INIT_MFA, jti=jti)

        # Generate an MFA secret for this user
        mfa_secret = pyotp.random_base32()

        # Encrypt and save the MFA secret into this user record
        AuthUserDb(table=AUTH_USER_TABLE, ssm=SSM).set_mfa_secret(
            mfa_secret=mfa_secret, username=username
        )

        # Generate an MFA provisioning URI for the user to register the MFA into their device
        mfa_provisioning_uri = TOTP(mfa_secret).provisioning_uri(
            name=email_addr, issuer_name="Darkord"
        )

        return common.gen_api_resp(
            code=2000,
            payload=ResponseSchema().load_and_dump(
                {"mfa_provisioning_uri": mfa_provisioning_uri}
            ),
        )

    except CommonException as err:
        # Only increment if error message is not Forbidden, else user keep trying will never be able to setup MFA
        if err.code != 4030:
            AuthAttemptDb(dynamodb=DYNAMODB, table=AUTH_ATTEMPT_TABLE).incr(
                action=auth_constants.ACTION_INIT_MFA, jti=jti
            )

        return common.gen_api_resp(code=err.code, msg=err.msg)

    except Exception as err:
        LOGGER.exception(err)
        return common.gen_api_resp(code=5000)
