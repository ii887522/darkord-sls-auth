import common
from common_decorators import log_event


@log_event
def handler(event, context):
    return common.gen_api_resp(code=2000)
