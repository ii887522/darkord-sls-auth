import common


def test_1_digit():
    assert len(common.gen_secret_digits(digit_count=1)) == 1


def test_2_digit():
    assert len(common.gen_secret_digits(digit_count=2)) == 2


def test_3_digit():
    assert len(common.gen_secret_digits(digit_count=3)) == 3


def test_6_digit():
    assert len(common.gen_secret_digits()) == 6
