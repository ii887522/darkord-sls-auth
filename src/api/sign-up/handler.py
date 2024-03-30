import logging

import common
from api_exception import ApiException
from common_decorators import log_event

LOGGER = logging.getLogger()


@log_event
def handler(event, context):
    try:
        return common.gen_api_resp(code=2000)

    except ApiException as err:
        return common.gen_api_resp(code=err.code, msg=err.msg)

    except Exception as err:
        LOGGER.exception(err)
        return common.gen_api_resp(code=5000)
