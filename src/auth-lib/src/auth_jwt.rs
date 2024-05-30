use crate::auth_enums::{Action, Role};
use serde::Serialize;

#[derive(Clone, Copy, Debug, Default, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionTokenType {
    #[default]
    Session,
}

#[derive(Debug, PartialEq, Serialize)]
pub struct AuthSessionToken {
    #[serde(default)]
    pub typ: SessionTokenType,

    pub jti: String,
    pub sub: String,
    pub name: String,
    pub exp: u64,
    pub aud: Action,
    pub dest: Action,
}

#[derive(Clone, Copy, Debug, Default, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RefreshTokenType {
    #[default]
    Refresh,
}

#[derive(Debug, PartialEq, Serialize)]
pub struct AuthRefreshToken {
    #[serde(default)]
    pub typ: RefreshTokenType,

    pub jti: String,
    pub exp: u64,
    pub aud: Action,
}

#[derive(Clone, Copy, Debug, Default, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessTokenType {
    #[default]
    Access,
}

#[derive(Debug, PartialEq, Serialize)]
pub struct AuthAccessToken {
    #[serde(default)]
    pub typ: AccessTokenType,

    pub jti: String,
    pub sub: String,
    pub name: String,
    pub exp: u64,
    pub roles: Vec<Role>,
    pub orig: String,
}
