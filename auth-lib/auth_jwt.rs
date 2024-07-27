use crate::auth_enums::{Action, Role};
use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct JwtTokenSecrets {
    pub access_token_secret: String,
    pub refresh_token_secret: String,
    pub session_token_secret: String,
}

#[derive(
    Clone, Copy, Debug, Default, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum SessionTokenType {
    #[default]
    Session,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct AuthSessionToken {
    #[serde(default)]
    pub typ: SessionTokenType,

    pub ver: u32,
    pub jti: String,
    pub sub: u32,
    pub exp: u64,
    pub src: Action,
    pub aud: Action,
    pub dest: Action,
}

#[derive(
    Clone, Copy, Debug, Default, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum RefreshTokenType {
    #[default]
    Refresh,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct AuthRefreshToken {
    #[serde(default)]
    pub typ: RefreshTokenType,

    pub ver: u32,
    pub jti: String,
    pub sub: u32,
    pub exp: u64,
    pub aud: Action,
}

#[derive(
    Clone, Copy, Debug, Default, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum AccessTokenType {
    #[default]
    Access,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct AuthAccessToken {
    #[serde(default)]
    pub typ: AccessTokenType,

    pub ver: u32,
    pub jti: String,
    pub sub: u32,
    pub exp: u64,
    pub roles: Vec<Role>,
    pub orig: String,
}
