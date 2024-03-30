import common


def test_with_msg():
    assert common.gen_api_resp(code=2000, msg="abc") == {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": '{"code": 2000, "message": "abc", "payload": {}}',
    }


def test_without_msg():
    assert common.gen_api_resp(code=4041, payload={"a": "hello"}) == {
        "statusCode": 404,
        "headers": {"Content-Type": "application/json"},
        "body": '{"code": 4041, "message": "Data was not found", "payload": {"a": "hello"}}',
    }


def test_unknown_code():
    assert common.gen_api_resp(code=4051) == {
        "statusCode": 405,
        "headers": {"Content-Type": "application/json"},
        "body": '{"code": 4051, "message": "", "payload": {}}',
    }
