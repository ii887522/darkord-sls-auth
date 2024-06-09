use crate::auth_enums::Action;
use common::constants;
use once_cell::sync::Lazy;
use std::env;

// SSM parameter paths
pub const JWT_TOKEN_PARAM_PATH: &str = "/auth/api/token";
pub const ACCESS_TOKEN_PARAM_PATH: &str = "/auth/api/token/access";
pub const REFRESH_TOKEN_PARAM_PATH: &str = "/auth/api/token/refresh";
pub const SESSION_TOKEN_PARAM_PATH: &str = "/auth/api/token/session";
pub const MFA_PARAM_PATH: &str = "/auth/api/mfa";

// DynamoDB table names
pub static AUTH_ATTEMPT_TABLE_NAME: Lazy<String> =
    Lazy::new(|| constants::STAGE_PREFIX.to_string() + "auth_attempt");
pub static AUTH_USER_TABLE_NAME: Lazy<String> =
    Lazy::new(|| constants::STAGE_PREFIX.to_string() + "auth_user");
pub static AUTH_VALID_TOKEN_PAIR_TABLE_NAME: Lazy<String> =
    Lazy::new(|| constants::STAGE_PREFIX.to_string() + "auth_valid_token_pair");
pub static AUTH_RBAC_TABLE_NAME: Lazy<String> =
    Lazy::new(|| constants::STAGE_PREFIX.to_string() + "auth_rbac");

// Max action attempts
pub static MAX_SIGN_UP_ATTEMPT: Lazy<u32> = Lazy::new(|| {
    env::var("MAX_SIGN_UP_ATTEMPT")
        .unwrap_or_else(|_| "0".to_string())
        .parse()
        .unwrap()
});
pub static MAX_VERIFY_ATTR_ATTEMPT: Lazy<u32> = Lazy::new(|| {
    env::var("MAX_VERIFY_ATTR_ATTEMPT")
        .unwrap_or_else(|_| "0".to_string())
        .parse()
        .unwrap()
});
pub static MAX_INIT_MFA_ATTEMPT: Lazy<u32> = Lazy::new(|| {
    env::var("MAX_INIT_MFA_ATTEMPT")
        .unwrap_or_else(|_| "0".to_string())
        .parse()
        .unwrap()
});
pub static MAX_LOGIN_ATTEMPT: Lazy<u32> = Lazy::new(|| {
    env::var("MAX_LOGIN_ATTEMPT")
        .unwrap_or_else(|_| "0".to_string())
        .parse()
        .unwrap()
});
pub static MAX_VERIFY_MFA_ATTEMPT: Lazy<u32> = Lazy::new(|| {
    env::var("MAX_VERIFY_MFA_ATTEMPT")
        .unwrap_or_else(|_| "0".to_string())
        .parse()
        .unwrap()
});

// JWT token types
pub const TOKEN_TYPE_ACCESS: &str = "access";
pub const TOKEN_TYPE_REFRESH: &str = "refresh";
pub const TOKEN_TYPE_SESSION: &str = "session";

pub const AUDIENCE_ACTIONS: &[Action] = &[
    Action::VerifyAttr,
    Action::InitMfa,
    Action::VerifyMfa,
    Action::Refresh,
];
