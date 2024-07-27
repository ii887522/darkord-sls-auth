use crate::auth_enums::Action;
use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Deserialize, Serialize)]
pub struct AuthUserContext {
    pub jti: String,

    #[serde(default)]
    pub sub: String,

    #[serde(default)]
    pub src: Option<Action>,

    #[serde(default)]
    pub dest: Option<Action>,

    #[serde(default)]
    pub orig: String,
}
