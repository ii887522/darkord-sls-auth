from decimal import Decimal

import common


def test_basic_data_types():
    assert common.mask_sensitive(data=None) is None
    assert common.mask_sensitive(data=True)
    assert common.mask_sensitive(data=3) == 3
    assert common.mask_sensitive(data=3.142) == 3.142
    assert common.mask_sensitive(data=Decimal("3.142")) == Decimal("3.142")
    assert common.mask_sensitive(data="abc") == "abc"


def test_list():
    assert common.mask_sensitive(data=[]) == []
    assert common.mask_sensitive(data=[None]) == [None]
    assert common.mask_sensitive(data=[False, -0]) == [False, -0]

    assert common.mask_sensitive(data=[-30.010, Decimal("-30.010"), ""]) == [
        -30.010,
        Decimal("-30.010"),
        "",
    ]


def test_dict():
    assert common.mask_sensitive(data={}) == {}
    assert common.mask_sensitive(data={"a": None}) == {"a": None}

    assert common.mask_sensitive(data={"b": False, "password": -0}) == {
        "b": False,
        "password": "****",
    }

    assert common.mask_sensitive(
        data={"code": -30.010, "jti": Decimal("-30.010"), "api-key": ""},
        extra_sensitive_params={"api-key"},
    ) == {"code": "****", "jti": "****", "api-key": "****"}


def test_tuple():
    assert common.mask_sensitive(data=()) == ()
    assert common.mask_sensitive(data=(None,)) == (None,)
    assert common.mask_sensitive(data=(False, -0)) == (False, -0)

    assert common.mask_sensitive(data=(-30.010, Decimal("-30.010"), "")) == (
        -30.010,
        Decimal("-30.010"),
        "",
    )
