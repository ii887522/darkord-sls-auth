import logging

import auth_constants
import common
from common_marshmallow import BaseSchema
from marshmallow import ValidationError, fields, pre_load, validates_schema

LOGGER = logging.getLogger()


class AuthAttemptDbSchema(BaseSchema):
    pk = fields.String(required=True)
    sk = fields.Constant("Attempt")
    action = fields.String(required=True)
    ip_addr = fields.String()
    jti = fields.String()
    attempt = fields.Integer(required=True)
    expired_at = fields.Integer()

    @pre_load
    def gen(self, data, **kwargs):
        action = common.convert_snake_case_to_pascal_case(src=data["action"])

        if data.get("ip_addr"):
            data["pk"] = f"{action}#{data['ip_addr']}"

        elif data.get("jti"):
            data["pk"] = f"{action}#{data['jti']}"

        return data

    @validates_schema
    def validate(self, data, **kwargs):
        if not data.get("ip_addr") and not data.get("jti"):
            raise ValidationError("Either ip_addr or jti must exist")


class AuthAttemptDb:
    def __init__(self, dynamodb, table):
        self.dynamodb = dynamodb
        self.table = table

    def incr(self, action: str, ip_addr="", jti="", attempt=1):
        expired_at = common.extend_current_timestamp(hours=1)

        try:
            attempt_item = {
                "action": action,
                "attempt": attempt,
                "expired_at": expired_at,
            }

            if ip_addr:
                attempt_item["ip_addr"] = ip_addr

            if jti:
                attempt_item["jti"] = jti

            db_resp = self.table.put_item(
                Item=AuthAttemptDbSchema().load_and_dump(attempt_item),
                ConditionExpression="attribute_not_exists(pk)",
            )
            LOGGER.debug("db_resp: %s", db_resp)

        except self.dynamodb.meta.client.exceptions.ConditionalCheckFailedException:
            db_resp = self.table.update_item(
                Key={
                    "pk": f"{common.convert_snake_case_to_pascal_case(src=action)}#{ip_addr or jti}",
                    "sk": "Attempt",
                },
                UpdateExpression="SET attempt = attempt + :incr, expired_at = :ea",
                ExpressionAttributeValues={":incr": attempt, ":ea": expired_at},
            )
            LOGGER.debug("db_resp: %s", db_resp)


def get_cond_check_transact_item(
    action: str,
    ip_addr: str,
    max_attempt: int,
    ret_val_on_cond_check_fail="ALL_OLD",
) -> dict:
    action = common.convert_snake_case_to_pascal_case(src=action)

    return {
        "ConditionCheck": {
            "TableName": auth_constants.AUTH_ATTEMPT_TABLE_NAME,
            "Key": {"pk": f"{action}#{ip_addr}", "sk": "Attempt"},
            # Temporarily block the user if they have already made maximum attempts to reduce brute-force attack
            "ConditionExpression": "attribute_not_exists(attempt) or attempt < :ma",
            "ExpressionAttributeValues": {":ma": max_attempt},
            "ReturnValuesOnConditionCheckFailure": ret_val_on_cond_check_fail,
        },
    }
