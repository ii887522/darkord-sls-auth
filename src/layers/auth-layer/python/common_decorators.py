import logging
import os

LOGGER = logging.getLogger()
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
LOG_FMT = "[%(levelname)s] %(message)s"

if len(LOGGER.handlers) > 0:
    # The Lambda environment pre-configures a handler logging to stderr. If a handler is already configured,
    # `logging.basicConfig` does not execute. Thus we set the level directly.
    LOGGER.setLevel(LOG_LEVEL)
    LOGGER.handlers[0].setFormatter(logging.Formatter(LOG_FMT))

else:
    logging.basicConfig(level=LOG_LEVEL, format=LOG_FMT)


def log_event(f):
    def inner(event, context):
        LOGGER.handlers[0].setFormatter(logging.Formatter("[EVENT] %(message)s"))
        LOGGER.info(event)
        LOGGER.handlers[0].setFormatter(logging.Formatter(LOG_FMT))
        return f(event, context)

    return inner
