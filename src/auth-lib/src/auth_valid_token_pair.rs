use crate::auth_constants;
use anyhow::{Context, Result};
use serde::Serialize;
use std::panic::Location;

#[derive(Clone, Copy, Debug, Default, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize)]
enum Sk {
    #[default]
    ValidTokenPair,
}

#[derive(Debug, PartialEq, Serialize)]
pub struct AuthValidTokenPair {
    pk: String,

    #[serde(default)]
    sk: Sk,

    refresh_token_jti: String,
    access_token_jti: String,
    expired_at: u64,
}

impl AuthValidTokenPair {
    pub fn new(refresh_token_jti: String, access_token_jti: String, expired_at: u64) -> Self {
        Self {
            pk: "RefreshToken#".to_string() + &refresh_token_jti,
            sk: Sk::ValidTokenPair,
            refresh_token_jti,
            access_token_jti,
            expired_at,
        }
    }
}

#[derive(Debug)]
pub struct AuthValidTokenPairDb<'a> {
    pub dynamodb: &'a aws_sdk_dynamodb::Client,
}

impl<'a> AuthValidTokenPairDb<'a> {
    pub async fn put_item(
        &'a self,
        refresh_token_jti: String,
        access_token_jti: String,
        expired_at: u64,
    ) -> Result<()> {
        let valid_token_pair =
            AuthValidTokenPair::new(refresh_token_jti, access_token_jti, expired_at);

        self.dynamodb
            .put_item()
            .table_name(&*auth_constants::AUTH_VALID_TOKEN_PAIR_TABLE_NAME)
            .set_item(Some(
                serde_dynamo::to_item(valid_token_pair).context(Location::caller())?,
            ))
            .condition_expression("attribute_not_exists(pk)")
            .send()
            .await
            .context(Location::caller())?;

        Ok(())
    }
}
