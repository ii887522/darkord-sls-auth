import common


def test():
    assert common.convert_snake_case_to_pascal_case(src="hello") == "Hello"
    assert common.convert_snake_case_to_pascal_case(src="hello_world") == "HelloWorld"

    assert (
        common.convert_snake_case_to_pascal_case(src="hello_world_123")
        == "HelloWorld123"
    )

    assert (
        common.convert_snake_case_to_pascal_case(src="hello_world_123_abc")
        == "HelloWorld123Abc"
    )
