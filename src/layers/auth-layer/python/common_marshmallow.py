import constants
import simplejson as json
from common_exception import CommonException
from marshmallow import EXCLUDE, RAISE, Schema, fields
from marshmallow.exceptions import ValidationError
from simplejson.errors import JSONDecodeError


class BaseSchema(Schema):
    class Meta:
        unknown = EXCLUDE if constants.STAGE == constants.PRODUCTION else RAISE

    def load_and_dump(self, data) -> dict:
        return dict(self.dump(self.load(data)))


class BaseRequestSchema(BaseSchema):
    def load_and_dump(self, event):
        try:
            path_params = event["pathParameters"] or {}
            qs_params = event["queryStringParameters"] or {}
            req_params = json.loads(event["body"] or "{}")
            return super().load_and_dump({**path_params, **qs_params, **req_params})

        except JSONDecodeError as err:
            raise CommonException(code=4000, msg=err.msg)

        except ValidationError as err:
            raise CommonException(code=4001, msg=str(err.messages))


class BaseResponseSchema(BaseSchema):
    pass


class TrimmedField(fields.Field):
    def __init__(self, inner, *args, **kwargs):
        self.inner = inner
        super().__init__(*args, **kwargs)

    def _bind_to_schema(self, field_name, parent):
        super()._bind_to_schema(field_name, parent)
        self.inner._bind_to_schema(field_name, parent)

    def _deserialize(self, value, *args, **kwargs):
        if hasattr(value, "strip"):
            value = value.strip()

        return self.inner._deserialize(value, *args, **kwargs)

    def _serialize(self, *args, **kwargs):
        return self.inner._serialize(*args, **kwargs)
