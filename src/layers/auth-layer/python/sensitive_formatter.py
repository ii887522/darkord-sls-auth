import logging
from typing import cast

import common


class SensitiveFormatter(logging.Formatter):
    def format(self, record):
        record.msg = common.mask_sensitive(data=record.msg)
        record.args = cast(tuple, common.mask_sensitive(data=record.args))
        return super().format(record)
