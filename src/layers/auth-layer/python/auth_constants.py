import os

import constants

# Languages
LANG_EN = "en"

# DynamoDB table names
AUTH_ATTEMPT_TABLE_NAME = f"{constants.STAGE_DASH_PREFIX}auth-attempt"
AUTH_USER_TABLE_NAME = f"{constants.STAGE_DASH_PREFIX}auth-user"

# SSM parameter names
SESSION_TOKEN_PARAM_NAME = "/auth/api/token/session"

# Actions
ACTION_SIGN_UP = "sign_up"
ACTION_VERIFY_ATTR = "verify_attr"
ACTION_INIT_MFA = "init_mfa"

# Environment variables
MAX_SIGN_UP_ATTEMPT = int(os.environ.get("MAX_SIGN_UP_ATTEMPT", 20))

# Token types
TOKEN_TYPE_SESSION = "session"
