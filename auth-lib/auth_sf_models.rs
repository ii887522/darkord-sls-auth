use serde::{Deserialize, Serialize};

#[derive(
    Clone, Copy, Debug, Default, Hash, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize,
)]
pub struct UpdateSecretsResponse {
    pub start_user_id: u32,
    pub end_user_id: u32,
}
