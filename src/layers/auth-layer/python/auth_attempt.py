import auth_constants
import common
import constants
from boto3.dynamodb.conditions import Attr
from common_marshmallow import BaseSchema
from marshmallow import ValidationError, fields, pre_load, validates_schema


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

    def get(self, action: str, ip_addr="", jti="") -> dict:
        action = common.convert_snake_case_to_pascal_case(src=action)

        db_resp = self.table.get_item(
            Key={"pk": f"{action}#{ip_addr or jti}", "sk": "Attempt"},
            ProjectionExpression="attempt,expired_at",
        )

        return db_resp.get("Item", {})

    def is_blocked(self, action: str, ip_addr="", jti="") -> bool:
        attempt = self.get(action=action, ip_addr=ip_addr, jti=jti)

        return bool(
            attempt
            and (attempt.get("expired_at") or constants.MAX_TIMESTAMP_IN_SECONDS)
            > common.get_current_timestamp()
            and attempt["attempt"] >= auth_constants.MAX_ACTION_ATTEMPT_DICT[action]
        )

    def incr(self, action: str, ip_addr="", jti="", attempt=1):
        expired_at = common.extend_current_timestamp(hours=1)

        try:
            self.table.update_item(
                Key={
                    "pk": f"{common.convert_snake_case_to_pascal_case(src=action)}#{ip_addr or jti}",
                    "sk": "Attempt",
                },
                UpdateExpression="SET attempt = attempt + :incr, expired_at = :ea",
                ConditionExpression=Attr("pk").exists(),
                ExpressionAttributeValues={":incr": attempt, ":ea": expired_at},
            )

        except self.dynamodb.meta.client.exceptions.ConditionalCheckFailedException:
            attempt_item = {
                "action": action,
                "attempt": attempt,
                "expired_at": expired_at,
            }

            if ip_addr:
                attempt_item["ip_addr"] = ip_addr

            if jti:
                attempt_item["jti"] = jti

            self.table.put_item(
                Item=AuthAttemptDbSchema().load_and_dump(attempt_item),
                ConditionExpression=Attr("pk").not_exists(),
            )

    def block(self, action: str, ip_addr="", jti="", is_permanent=False):
        expired_at = common.extend_current_timestamp(
            minutes=(
                auth_constants.JWT_TOKEN_VALIDITY_IN_MINUTES_DICT[action] if jti else 60
            )
        )

        try:
            self.table.update_item(
                Key={
                    "pk": f"{common.convert_snake_case_to_pascal_case(src=action)}#{ip_addr or jti}",
                    "sk": "Attempt",
                },
                UpdateExpression="SET attempt = :a, expired_at = :ea",
                ConditionExpression=Attr("pk").exists(),
                ExpressionAttributeValues={
                    ":a": auth_constants.MAX_ACTION_ATTEMPT_DICT[action],
                    ":ea": None if is_permanent else expired_at,
                },
            )

        except self.dynamodb.meta.client.exceptions.ConditionalCheckFailedException:
            attempt_item = {
                "action": action,
                "attempt": auth_constants.MAX_ACTION_ATTEMPT_DICT[action],
                "expired_at": expired_at,
            }

            if ip_addr:
                attempt_item["ip_addr"] = ip_addr

            if jti:
                attempt_item["jti"] = jti

            self.table.put_item(
                Item=AuthAttemptDbSchema().load_and_dump(attempt_item),
                ConditionExpression=Attr("pk").not_exists(),
            )
