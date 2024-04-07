from boto3.dynamodb.types import TypeDeserializer, TypeSerializer


def deserialize_item(item: dict) -> dict:
    deserializer = TypeDeserializer()
    return {k: deserializer.deserialize(v) for k, v in item.items()}


def serialize_item(item: dict) -> dict:
    serializer = TypeSerializer()
    return {k: serializer.serialize(v) for k, v in item.items()}
