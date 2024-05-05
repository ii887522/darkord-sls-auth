from boto3.dynamodb.conditions import Attr
from common_marshmallow import BaseSchema
from marshmallow import fields, pre_load


class AuthValidTokenPairDbSchema(BaseSchema):
    pk = fields.String(required=True)
    sk = fields.Constant("ValidTokenPair")
    refresh_token_jti = fields.String(required=True)
    access_token_jti = fields.String(required=True)
    expired_at = fields.Integer(required=True)

    @pre_load
    def gen(self, data, **kwargs):
        data["pk"] = f"RefreshToken#{data['refresh_token_jti']}"
        return data


class AuthValidTokenPairDb:
    def __init__(self, table):
        self.table = table

    def get(self, refresh_token_jti: str) -> dict:
        db_resp = self.table.get_item(
            Key={"pk": f"RefreshToken#{refresh_token_jti}"},
            ProjectionExpression="access_token_jti,expired_at",
        )

        return db_resp.get("Item", {})

    def put(self, refresh_token_jti: str, access_token_jti: str, expired_at: int):
        self.table.put_item(
            Item=AuthValidTokenPairDbSchema().load_and_dump(
                {
                    "refresh_token_jti": refresh_token_jti,
                    "access_token_jti": access_token_jti,
                    "expired_at": expired_at,
                }
            ),
            ConditionExpression=Attr("pk").not_exists(),
        )
