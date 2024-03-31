import logging

import boto3
import common
import constants
from api_exception import ApiException
from botocore.config import Config
from common_decorators import log_event

LOGGER = logging.getLogger()

DYNAMODB = boto3.resource(
    "dynamodb", constants.REGION, config=Config(tcp_keepalive=True)
)


@log_event
def handler(event, context):
    try:
        return common.gen_api_resp(code=2000)

    except ApiException as err:
        return common.gen_api_resp(code=err.code, msg=err.msg)

    except Exception as err:
        LOGGER.exception(err)
        return common.gen_api_resp(code=5000)
