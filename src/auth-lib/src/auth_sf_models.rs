use serde::Deserialize;

#[derive(Clone, Copy, Debug, Default, Hash, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
pub struct UpdateSecretsResponse {
    start_user_id: u32,
    end_user_id: u32,
}
