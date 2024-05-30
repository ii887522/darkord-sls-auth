use crate::auth_enums::Action;
use common::constants;
use once_cell::sync::Lazy;
use std::{collections::HashMap, env};

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
pub static MAX_ACTION_ATTEMPT_MAP: Lazy<HashMap<Action, u32>> = Lazy::new(|| {
    HashMap::from_iter([
        (
            Action::SignUp,
            env::var("MAX_SIGN_UP_ATTEMPT")
                .unwrap_or_else(|_| "0".to_string())
                .parse()
                .unwrap(),
        ),
        (
            Action::VerifyAttr,
            env::var("MAX_VERIFY_ATTR_ATTEMPT")
                .unwrap_or_else(|_| "0".to_string())
                .parse()
                .unwrap(),
        ),
        (
            Action::InitMfa,
            env::var("MAX_INIT_MFA_ATTEMPT")
                .unwrap_or_else(|_| "0".to_string())
                .parse()
                .unwrap(),
        ),
        (
            Action::Login,
            env::var("MAX_LOGIN_ATTEMPT")
                .unwrap_or_else(|_| "0".to_string())
                .parse()
                .unwrap(),
        ),
        (
            Action::VerifyMfa,
            env::var("MAX_VERIFY_MFA_ATTEMPT")
                .unwrap_or_else(|_| "0".to_string())
                .parse()
                .unwrap(),
        ),
    ])
});

pub static JWT_TOKEN_VALIDITY_IN_MINUTES_MAP: Lazy<HashMap<Action, u64>> = Lazy::new(|| {
    HashMap::from_iter([
        (Action::VerifyAttr, 3),
        (Action::InitMfa, 3),
        (Action::VerifyMfa, 3),
    ])
});
