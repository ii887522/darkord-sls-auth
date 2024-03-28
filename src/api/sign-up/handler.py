import json

from common_decorators import log_event


@log_event
def handler(event, context):
    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({}),
    }
