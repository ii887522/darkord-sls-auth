import os

import constants

# Languages
LANG_EN = "en"

# DynamoDB table names
AUTH_ATTEMPT_TABLE_NAME = f"{constants.STAGE_DASH_PREFIX}auth-attempt"
AUTH_USER_TABLE_NAME = f"{constants.STAGE_DASH_PREFIX}auth-user"

# Actions
ACTION_SIGN_UP = "sign_up"

# Environment variables
MAX_SIGN_UP_ATTEMPT = int(os.environ.get("MAX_SIGN_UP_ATTEMPT", 20))
