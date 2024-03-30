from decimal import Decimal

import simplejson as json

SENSITIVE_PARAMS = {
    "Postman-Token",
    "x-api-key",
    "apiKey",
    "apiKeyId",
    "accessKey",
    "password",
    "session_token",
    "code",
    "refresh_token",
    "access_token",
    "jti",
    "verification_code",
    "authorizationToken",
}

API_ERR_MSG = {
    400: "Bad request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Data was not found",
    409: "Conflict",
    500: "Internal server error",
}


def mask_sensitive(data, extra_senstive_params: set[str] = set()):
    if data is None or isinstance(data, (bool, int, float, Decimal, str)):
        return data

    if isinstance(data, list):
        return [
            mask_sensitive(data=v, extra_senstive_params=extra_senstive_params)
            for v in data
        ]

    if isinstance(data, dict):
        for k in data:
            data[k] = (
                "****"
                if k in SENSITIVE_PARAMS.union(extra_senstive_params)
                else mask_sensitive(
                    data=data[k], extra_senstive_params=extra_senstive_params
                )
            )

        return data

    if isinstance(data, tuple):
        return tuple(
            mask_sensitive(data=v, extra_senstive_params=extra_senstive_params)
            for v in data
        )

    return data


def gen_api_resp(code: int, headers: dict = {}, msg="", payload: dict = {}):
    status_code = int(str(code)[:3])

    return {
        "statusCode": status_code,
        "headers": {"Content-Type": "application/json", **headers},
        "body": json.dumps(
            {
                "code": code,
                "message": msg if msg else API_ERR_MSG.get(status_code, ""),
                "payload": payload,
            }
        ),
    }
