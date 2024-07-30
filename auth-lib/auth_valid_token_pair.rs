use crate::auth_constants;
use anyhow::{bail, Context, Error, Result};
use aws_sdk_dynamodb::{
    error::SdkError,
    operation::{delete_item::DeleteItemError, update_item::UpdateItemError},
    types::AttributeValue,
};
use common::CommonError;
use serde::{Deserialize, Serialize};
use std::panic::Location;

#[derive(
    Clone, Copy, Debug, Default, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize,
)]
enum Sk {
    #[default]
    ValidTokenPair,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct AuthValidTokenPair {
    pk: String,

    #[serde(default)]
    sk: Sk,

    pub refresh_token_jti: String,
    pub access_token_jti: String,
    pub expired_at: u64,
}

impl AuthValidTokenPair {
    fn new(refresh_token_jti: String, access_token_jti: String, expired_at: u64) -> Self {
        Self {
            pk: format!("RefreshToken#{refresh_token_jti}"),
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
    pub async fn put_valid_token_pair(
        &self,
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

    pub async fn update_valid_token_pair(
        &self,
        refresh_token_jti: &str,
        access_token_jti: &str,
    ) -> Result<()> {
        let db_resp = self
            .dynamodb
            .update_item()
            .table_name(&*auth_constants::AUTH_VALID_TOKEN_PAIR_TABLE_NAME)
            .key(
                "pk",
                AttributeValue::S(format!("RefreshToken#{refresh_token_jti}")),
            )
            .key("sk", AttributeValue::S("ValidTokenPair".to_string()))
            .update_expression("SET access_token_jti = :atj")
            .condition_expression("attribute_exists(pk)")
            .expression_attribute_values(":atj", AttributeValue::S(access_token_jti.to_string()))
            .send()
            .await
            .context(Location::caller());

        if let Err(err) = db_resp {
            let err = err
                .downcast::<SdkError<_>>()
                .context(Location::caller())?
                .into_service_error();

            if let UpdateItemError::ConditionalCheckFailedException(_) = err {
                let err = CommonError {
                    code: 4010,
                    ..Default::default()
                };

                bail!(err);
            } else {
                return Err(Error::from(err).context(Location::caller()));
            }
        }

        Ok(())
    }

    pub async fn get_valid_token_pair(
        &self,
        refresh_token_jti: &str,
    ) -> Result<Option<AuthValidTokenPair>> {
        let db_resp = self
            .dynamodb
            .get_item()
            .table_name(&*auth_constants::AUTH_VALID_TOKEN_PAIR_TABLE_NAME)
            .key(
                "pk",
                AttributeValue::S(format!("RefreshToken#{refresh_token_jti}")),
            )
            .key("sk", AttributeValue::S("ValidTokenPair".to_string()))
            .projection_expression("pk,refresh_token_jti,access_token_jti,expired_at")
            .send()
            .await
            .context(Location::caller())?;

        db_resp.item.map_or(Ok(None), |item| {
            serde_dynamo::from_item(item).context(Location::caller())
        })
    }

    pub async fn delete_valid_token_pair(&self, refresh_token_jti: &str) -> Result<()> {
        let db_resp = self
            .dynamodb
            .delete_item()
            .table_name(&*auth_constants::AUTH_VALID_TOKEN_PAIR_TABLE_NAME)
            .key(
                "pk",
                AttributeValue::S(format!("RefreshToken#{refresh_token_jti}")),
            )
            .key("sk", AttributeValue::S("ValidTokenPair".to_string()))
            .condition_expression("attribute_exists(pk)")
            .send()
            .await
            .context(Location::caller());

        if let Err(err) = db_resp {
            let err = err
                .downcast::<SdkError<_>>()
                .context(Location::caller())?
                .into_service_error();

            if let DeleteItemError::ConditionalCheckFailedException(_) = err {
                let err = CommonError {
                    code: 4001,
                    message: "User already logged out".to_string(),
                };

                bail!(err);
            } else {
                return Err(Error::from(err).context(Location::caller()));
            }
        }

        Ok(())
    }
}
