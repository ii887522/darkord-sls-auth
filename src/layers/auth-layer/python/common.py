import hashlib
import os
import secrets
import time
from decimal import Decimal
from typing import Literal

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


def mask_sensitive(data, extra_sensitive_params: set[str] = set()):
    if data is None or isinstance(data, (bool, int, float, Decimal, str)):
        return data

    if isinstance(data, list):
        return [
            mask_sensitive(data=v, extra_sensitive_params=extra_sensitive_params)
            for v in data
        ]

    if isinstance(data, dict):
        sensitive_params = SENSITIVE_PARAMS.union(extra_sensitive_params)

        for k in data:
            data[k] = (
                "****"
                if k in sensitive_params
                else mask_sensitive(
                    data=data[k], extra_sensitive_params=extra_sensitive_params
                )
            )

        return data

    if isinstance(data, tuple):
        return tuple(
            mask_sensitive(data=v, extra_sensitive_params=extra_sensitive_params)
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
                "message": msg or API_ERR_MSG.get(status_code, ""),
                "payload": payload,
            },
        ),
    }


def convert_snake_case_to_pascal_case(src: str) -> str:
    return src.replace("_", " ").title().replace(" ", "")


def hash_secret(secret: str) -> tuple[str, str]:
    salt = os.urandom(32)

    hash = hashlib.scrypt(
        secret.encode(),
        salt=salt,
        n=16384,
        r=8,
        p=1,
    )

    return hash.hex(), salt.hex()


def gen_secret_digits(digit_count=6) -> str:
    return str(secrets.randbelow(10**digit_count)).zfill(digit_count)


def get_current_timestamp(unit: Literal["seconds", "milliseconds"] = "seconds") -> int:
    resp = time.time()

    if unit == "milliseconds":
        resp *= 1000

    return int(resp)


def extend_current_timestamp(
    src_timestamp=0,
    years=0,
    months=0,
    days=0,
    hours=0,
    minutes=0,
    seconds=0,
    milliseconds=0,
    unit: Literal["seconds", "milliseconds"] = "seconds",
) -> int:
    # Convert and do everything in milliseconds to make logic simpler

    if unit == "seconds":
        # src_timestamp is in seconds, need to convert to milliseconds
        src_timestamp *= 1000

    resp = (
        (src_timestamp or get_current_timestamp(unit="milliseconds"))
        + years * 31_536_000_000
        + months * 2_592_000_000
        + days * 86_400_000
        + hours * 3_600_000
        + minutes * 60_000
        + seconds * 1_000
        + milliseconds
    )

    if unit == "seconds":
        resp //= 1000

    return resp
