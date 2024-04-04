import auth_constants
from common_marshmallow import BaseSchema
from marshmallow import ValidationError, fields, pre_load, validates_schema


class AuthUserDbSchema(BaseSchema):
    pk = fields.String(required=True)
    sk = fields.Constant("User")
    username = fields.String(required=True)
    email_addr = fields.Email(required=True)
    password = fields.String()
    salt = fields.String()
    locale = fields.String()
    extra = fields.Dict()
    verified_attrs = fields.List(fields.String())
    verification_code = fields.String()
    code_expired_at = fields.Integer()

    @pre_load
    def gen(self, data, **kwargs):
        if not data.get("password"):
            data["pk"] = f"Username#{data['username']}"

        elif not data.get("verification_code"):
            data["pk"] = f"EmailAddr#{data['email_addr']}"

        return data

    @validates_schema
    def validate(self, data, **kwargs):
        pk = data["pk"]

        if pk.startswith("Username#"):
            if not data.get("password"):
                raise ValidationError("password is required")

            if not data.get("salt"):
                raise ValidationError("salt is required")

            if not data.get("locale"):
                raise ValidationError("locale is required")

        elif pk.startswith("EmailAddr#"):
            if not data.get("verification_code"):
                raise ValidationError("verification_code is required")

            if not data.get("code_expired_at"):
                raise ValidationError("code_expired_at is required")


def get_put_transact_item(
    username: str,
    email_addr: str,
    password="",
    salt="",
    locale="",
    extra: dict = {},
    verification_code="",
    code_expired_at=0,
    ret_val_on_cond_check_fail="ALL_OLD",
) -> dict:
    item: dict = {"username": username, "email_addr": email_addr}

    if password:
        item["password"] = password

    if salt:
        item["salt"] = salt

    if locale:
        item["locale"] = locale

    if extra:
        item["extra"] = extra

    if verification_code:
        item["verification_code"] = verification_code

    if code_expired_at:
        item["code_expired_at"] = code_expired_at

    return {
        "Put": {
            "TableName": auth_constants.AUTH_USER_TABLE_NAME,
            "Item": AuthUserDbSchema().load_and_dump(item),
            "ConditionExpression": "attribute_not_exists(pk)",
            "ReturnValuesOnConditionCheckFailure": ret_val_on_cond_check_fail,
        }
    }
