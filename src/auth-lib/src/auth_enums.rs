use crate::auth_jwt::{AuthAccessToken, AuthRefreshToken, AuthSessionToken};
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
