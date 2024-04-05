import common


def test_seconds_no_extend():
    assert (
        common.extend_current_timestamp(
            src_timestamp=1_000_000_000,
            years=0,
            months=0,
            days=0,
            hours=0,
            minutes=0,
            seconds=0,
            milliseconds=0,
        )
        == 1_000_000_000
    )


def test_seconds_extend_millseconds():
    assert (
        common.extend_current_timestamp(
            src_timestamp=1_000_000_000,
            years=0,
            months=0,
            days=0,
            hours=0,
            minutes=0,
            seconds=0,
            milliseconds=1,
        )
        == 1_000_000_000
    )


def test_seconds_extend_seconds():
    assert (
        common.extend_current_timestamp(
            src_timestamp=1_000_000_000,
            years=0,
            months=0,
            days=0,
            hours=0,
            minutes=0,
            seconds=1,
            milliseconds=0,
        )
        == 1_000_000_001
    )


def test_seconds_extend_minutes():
    assert (
        common.extend_current_timestamp(
            src_timestamp=1_000_000_000,
            years=0,
            months=0,
            days=0,
            hours=0,
            minutes=1,
            seconds=0,
            milliseconds=0,
        )
        == 1_000_000_060
    )


def test_seconds_extend_hours():
    assert (
        common.extend_current_timestamp(
            src_timestamp=1_000_000_000,
            years=0,
            months=0,
            days=0,
            hours=1,
            minutes=0,
            seconds=0,
            milliseconds=0,
        )
        == 1_000_003_600
    )


def test_seconds_extend_days():
    assert (
        common.extend_current_timestamp(
            src_timestamp=1_000_000_000,
            years=0,
            months=0,
            days=1,
            hours=0,
            minutes=0,
            seconds=0,
            milliseconds=0,
        )
        == 1_000_086_400
    )


def test_seconds_extend_months():
    assert (
        common.extend_current_timestamp(
            src_timestamp=1_000_000_000,
            years=0,
            months=1,
            days=0,
            hours=0,
            minutes=0,
            seconds=0,
            milliseconds=0,
        )
        == 1_002_592_000
    )


def test_seconds_extend_years():
    assert (
        common.extend_current_timestamp(
            src_timestamp=1_000_000_000,
            years=1,
            months=0,
            days=0,
            hours=0,
            minutes=0,
            seconds=0,
            milliseconds=0,
        )
        == 1_031_536_000
    )


def test_seconds_extend_all_metrics():
    assert (
        common.extend_current_timestamp(
            src_timestamp=1_000_000_000,
            years=1,
            months=1,
            days=1,
            hours=1,
            minutes=1,
            seconds=1,
            milliseconds=1,
        )
        == 1_034_218_061
    )


def test_milliseconds_extend_all_metrics():
    assert (
        common.extend_current_timestamp(
            src_timestamp=1_000_000_000_000,
            years=1,
            months=1,
            days=1,
            hours=1,
            minutes=1,
            seconds=1,
            milliseconds=1,
            unit="milliseconds",
        )
        == 1_034_218_061_001
    )
