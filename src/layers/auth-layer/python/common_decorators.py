import logging

import constants
from sensitive_formatter import SensitiveFormatter

LOGGER = logging.getLogger()
LOG_FMT = "[%(levelname)s] [%(pathname)s:%(lineno)d] %(message)s"

if len(LOGGER.handlers) > 0:
    # The Lambda environment pre-configures a handler logging to stderr. If a handler is already configured,
    # `logging.basicConfig` does not execute.
    LOGGER.setLevel(constants.LOG_LEVEL)

else:
    logging.basicConfig(level=constants.LOG_LEVEL, format=LOG_FMT)

LOGGER.handlers[0].setFormatter(SensitiveFormatter(LOG_FMT))


def log_event(f):
    def handler(event, context):
        LOGGER.handlers[0].setFormatter(
            SensitiveFormatter("[EVENT] [%(pathname)s:%(lineno)d] %(message)s")
        )

        LOGGER.info(event)
        LOGGER.handlers[0].setFormatter(SensitiveFormatter(LOG_FMT))
        return f(event, context)

    return handler
