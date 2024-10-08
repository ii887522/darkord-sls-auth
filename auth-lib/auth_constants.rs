use crate::auth_enums::Action;
use common::constants;
use std::env;

// SSM parameter paths
pub const ACCESS_TOKEN_PARAM_PATH: &str = "/auth/api/token/access";
pub const REFRESH_TOKEN_PARAM_PATH: &str = "/auth/api/token/refresh";
pub const SESSION_TOKEN_PARAM_PATH: &str = "/auth/api/token/session";
pub const MFA_PARAM_PATH: &str = "/auth/api/mfa";

// JWT token types
pub const TOKEN_TYPE_ACCESS: &str = "access";
pub const TOKEN_TYPE_REFRESH: &str = "refresh";
pub const TOKEN_TYPE_SESSION: &str = "session";

pub const AUDIENCE_ACTIONS: &[Action] = &[
    Action::VerifyAttr,
    Action::InitMfa,
    Action::VerifyMfa,
    Action::Refresh,
    Action::ResetPassword,
];

// Validities in minutes
pub const VERIFICATION_CODE_VALIDITY_IN_MINUTES: i64 = 5;

thread_local! {
    // DynamoDB table names
    pub static AUTH_ATTEMPT_TABLE_NAME: String = constants::STAGE_PREFIX.with(|stage_prefix| format!("{stage_prefix}auth_attempt"));
    pub static AUTH_USER_TABLE_NAME: String = constants::STAGE_PREFIX.with(|stage_prefix| format!("{stage_prefix}auth_user"));
    pub static AUTH_VALID_TOKEN_PAIR_TABLE_NAME: String = constants::STAGE_PREFIX.with(|stage_prefix| format!("{stage_prefix}auth_valid_token_pair"));
    pub static AUTH_RBAC_TABLE_NAME: String = constants::STAGE_PREFIX.with(|stage_prefix| format!("{stage_prefix}auth_rbac"));

    // Max action attempts
    pub static MAX_SIGN_UP_ATTEMPT: u32 =
        env::var("MAX_SIGN_UP_ATTEMPT").unwrap_or_else(|_| "0".to_string()).parse().unwrap();
    pub static MAX_VERIFY_ATTR_ATTEMPT: u32 =
        env::var("MAX_VERIFY_ATTR_ATTEMPT").unwrap_or_else(|_| "0".to_string()).parse().unwrap();
    pub static MAX_INIT_MFA_ATTEMPT: u32 =
        env::var("MAX_INIT_MFA_ATTEMPT").unwrap_or_else(|_| "0".to_string()).parse().unwrap();
    pub static MAX_LOGIN_ATTEMPT: u32 =
        env::var("MAX_LOGIN_ATTEMPT").unwrap_or_else(|_| "0".to_string()).parse().unwrap();
    pub static MAX_VERIFY_MFA_ATTEMPT: u32 =
        env::var("MAX_VERIFY_MFA_ATTEMPT").unwrap_or_else(|_| "0".to_string()).parse().unwrap();
    pub static MAX_RESET_PASSWORD_ATTEMPT: u32 =
        env::var("MAX_RESET_PASSWORD_ATTEMPT").unwrap_or_else(|_| "0".to_string()).parse().unwrap();

    // API key names
    pub static REST_API_KEY_NAME: String = env::var("REST_API_KEY_NAME").unwrap();
    pub static WS_API_KEY_NAME: String = env::var("WS_API_KEY_NAME").unwrap();

    // API usage plan IDs
    pub static REST_API_USAGE_PLAN_ID: String = env::var("REST_API_USAGE_PLAN_ID").unwrap();
    pub static WS_API_USAGE_PLAN_ID: String = env::var("WS_API_USAGE_PLAN_ID").unwrap();

    // CloudFront distributions configurations
    pub static CF_DISTRIBUTION_ID: String = env::var("CF_DISTRIBUTION_ID").unwrap();
    pub static CF_ORIGIN_REST_API_DOMAIN_NAME: String = env::var("CF_ORIGIN_REST_API_DOMAIN_NAME").unwrap();
    pub static CF_ORIGIN_WS_API_DOMAIN_NAME: String = env::var("CF_ORIGIN_WS_API_DOMAIN_NAME").unwrap();
}
