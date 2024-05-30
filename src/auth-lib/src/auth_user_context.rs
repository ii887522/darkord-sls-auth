use crate::auth_enums::Action;
use serde::Deserialize;

#[derive(Debug, PartialEq, Deserialize)]
pub struct AuthUserContext {
    pub jti: String,

    #[serde(default)]
    pub sub: String,

    #[serde(default)]
    pub name: String,

    #[serde(default)]
    pub dest: Option<Action>,
}
