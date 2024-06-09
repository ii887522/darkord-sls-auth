use crate::{
    auth_constants,
    auth_jwt::{AuthAccessToken, AuthRefreshToken, AuthSessionToken},
};
use common::StringExt;
use serde::{Deserialize, Serialize};
use std::fmt::{self, Display, Formatter};

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    SignUp,
    VerifyAttr,
    InitMfa,
    Login,
    VerifyMfa,
    Refresh,
}

impl Action {
    pub fn get_max_attempt(&self) -> u32 {
        match self {
            Action::SignUp => *auth_constants::MAX_SIGN_UP_ATTEMPT,
            Action::VerifyAttr => *auth_constants::MAX_VERIFY_ATTR_ATTEMPT,
            Action::InitMfa => *auth_constants::MAX_INIT_MFA_ATTEMPT,
            Action::Login => *auth_constants::MAX_LOGIN_ATTEMPT,
            Action::VerifyMfa => *auth_constants::MAX_VERIFY_MFA_ATTEMPT,
            Action::Refresh => u32::MAX,
        }
    }

    pub const fn get_jwt_token_validity_in_minutes(&self) -> u64 {
        match self {
            Action::SignUp => 0,
            Action::VerifyAttr => 5,
            Action::InitMfa => 5,
            Action::Login => 0,
            Action::VerifyMfa => 5,
            Action::Refresh => 24 * 60, // 1 day
        }
    }
}

impl Display for Action {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(
            formatter,
            "{}",
            serde_json::to_string(self)
                .unwrap()
                .remove_first_and_last_chars()
        )
    }
}

#[derive(
    Clone, Copy, Debug, Default, Hash, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum Locale {
    #[default]
    En,
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UserAttr {
    EmailAddr,
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    User,
}

#[derive(Debug, PartialEq, Deserialize)]
pub enum JwtToken {
    Access(AuthAccessToken),
    Refresh(AuthRefreshToken),
    Session(AuthSessionToken),
}
