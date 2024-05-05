import os

import constants

# Languages
LANG_EN = "en"

# DynamoDB table names
AUTH_ATTEMPT_TABLE_NAME = f"{constants.STAGE_PREFIX}auth_attempt"
AUTH_USER_TABLE_NAME = f"{constants.STAGE_PREFIX}auth_user"
AUTH_VALID_TOKEN_PAIR_TABLE_NAME = f"{constants.STAGE_PREFIX}auth_valid_token_pair"
AUTH_RBAC_TABLE_NAME = f"{constants.STAGE_PREFIX}auth_rbac"

# SSM parameter paths
JWT_TOKEN_PARAM_PATH = "/auth/api/token"
ACCESS_TOKEN_PARAM_PATH = "/auth/api/token/access"
REFRESH_TOKEN_PARAM_PATH = "/auth/api/token/refresh"
SESSION_TOKEN_PARAM_PATH = "/auth/api/token/session"
MFA_PARAM_PATH = "/auth/api/mfa"

# Actions
ACTION_SIGN_UP = "sign_up"
ACTION_VERIFY_ATTR = "verify_attr"
ACTION_INIT_MFA = "init_mfa"
ACTION_LOGIN = "login"
ACTION_VERIFY_MFA_CODE = "verify_mfa_code"
AUDIENCE_ACTIONS = (ACTION_VERIFY_ATTR, ACTION_INIT_MFA, ACTION_VERIFY_MFA_CODE)

# Max action attempts
MAX_ACTION_ATTEMPT_DICT = {
    ACTION_SIGN_UP: int(os.environ.get("MAX_SIGN_UP_ATTEMPT", 0)),
    ACTION_VERIFY_ATTR: int(os.environ.get("MAX_VERIFY_ATTR_ATTEMPT", 0)),
    ACTION_INIT_MFA: int(os.environ.get("MAX_INIT_MFA_ATTEMPT", 0)),
    ACTION_LOGIN: int(os.environ.get("MAX_LOGIN_ATTEMPT", 0)),
    ACTION_VERIFY_MFA_CODE: int(os.environ.get("MAX_VERIFY_MFA_CODE_ATTEMPT", 0)),
}

# Action JWT token validities
JWT_TOKEN_VALIDITY_IN_MINUTES_DICT = {
    ACTION_VERIFY_ATTR: 3,
    ACTION_INIT_MFA: 3,
    ACTION_VERIFY_MFA_CODE: 3,
}

# Token types
TOKEN_TYPE_ACCESS = "access"
TOKEN_TYPE_REFRESH = "refresh"
TOKEN_TYPE_SESSION = "session"

# Roles
ROLE_USER = "user"
