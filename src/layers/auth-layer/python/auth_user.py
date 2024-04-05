import auth_constants
from common_marshmallow import BaseSchema
from marshmallow import ValidationError, fields, post_load, pre_load, validates_schema


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
        if data.get("password"):
            data["pk"] = f"Username#{data['username']}"

        elif data.get("verification_code"):
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

    @post_load
    def convert_list_to_set(self, data, **kwargs):
        verified_attrs = data.get("verified_attrs")

        if verified_attrs:
            data["verified_attrs"] = set(verified_attrs)

        else:
            data.pop("verified_attrs", None)

        return data


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
    user: dict = {"username": username, "email_addr": email_addr}

    if password:
        user["password"] = password

    if salt:
        user["salt"] = salt

    if locale:
        user["locale"] = locale

    if extra:
        user["extra"] = extra

    if verification_code:
        user["verification_code"] = verification_code

    if code_expired_at:
        user["code_expired_at"] = code_expired_at

    return {
        "Put": {
            "TableName": auth_constants.AUTH_USER_TABLE_NAME,
            "Item": AuthUserDbSchema().load_and_dump(user),
            "ConditionExpression": "attribute_not_exists(pk)",
            "ReturnValuesOnConditionCheckFailure": ret_val_on_cond_check_fail,
        }
    }
