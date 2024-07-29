use crate::{auth_constants, auth_enums::Action};
use anyhow::{Context, Error, Result};
use aws_sdk_dynamodb::{
    error::SdkError, operation::update_item::UpdateItemError::ConditionalCheckFailedException,
    types::AttributeValue,
};
use common::{self, Case};
use optarg2chain::optarg_impl;
use serde::{Deserialize, Serialize};
use std::panic::Location;

#[derive(
    Clone, Copy, Debug, Default, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize,
)]
enum Sk {
    #[default]
    Attempt,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct AuthAttempt {
    pk: String,

    #[serde(default)]
    sk: Sk,

    action: Action,

    #[serde(default, skip_serializing_if = "String::is_empty")]
    ip_addr: String,

    #[serde(default, skip_serializing_if = "String::is_empty")]
    jti: String,

    attempt: u32,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    expired_at: Option<u64>,
}

#[optarg_impl]
impl AuthAttempt {
    #[optarg_method(AuthAttemptNewBuilder, call)]
    fn new(
        action: Action,
        #[optarg_default] ip_addr: String,
        #[optarg_default] jti: String,
        attempt: u32,
        expired_at: u64,
    ) -> Self {
        let pk_action = action.to_string().convert_snake_case_to_pascal_case();

        Self {
            pk: if !ip_addr.is_empty() {
                format!("{pk_action}#{ip_addr}")
            } else if !jti.is_empty() {
                format!("{pk_action}#{jti}")
            } else {
                panic!("Unable to build pk")
            },
            sk: Sk::Attempt,
            action,
            ip_addr,
            jti,
            attempt,
            expired_at: Some(expired_at),
        }
    }
}

#[derive(Debug)]
pub struct AuthAttemptDb<'a> {
    pub dynamodb: &'a aws_sdk_dynamodb::Client,
}

#[optarg_impl]
impl<'a> AuthAttemptDb<'a> {
    #[optarg_method(AuthAttemptDbGetItemBuilder, send)]
    pub async fn get_attempt<'b, 'c>(
        &'b self,
        action: Action,
        #[optarg_default] ip_addr: &'c str,
        #[optarg_default] jti: &'c str,
    ) -> Result<Option<AuthAttempt>> {
        let db_resp = self
            .dynamodb
            .get_item()
            .table_name(&*auth_constants::AUTH_ATTEMPT_TABLE_NAME)
            .key(
                "pk",
                AttributeValue::S(format!(
                    "{action}#{id}",
                    action = action.to_string().convert_snake_case_to_pascal_case(),
                    id = if !ip_addr.is_empty() {
                        ip_addr
                    } else if !jti.is_empty() {
                        jti
                    } else {
                        panic!("Unable to find id")
                    }
                )),
            )
            .key("sk", AttributeValue::S("Attempt".to_string()))
            .projection_expression("pk,#action,attempt,expired_at")
            .expression_attribute_names("#action", "action")
            .send()
            .await
            .context(Location::caller())?;

        db_resp.item.map_or(Ok(None), |item| {
            serde_dynamo::from_item(item).context(Location::caller())
        })
    }

    #[optarg_method(AuthAttemptDbIsBlockedBuilder, send)]
    pub async fn is_blocked<'b, 'c>(
        &'b self,
        action: Action,
        #[optarg_default] ip_addr: &'c str,
        #[optarg_default] jti: &'c str,
    ) -> Result<bool> {
        if let Some(attempt) = self
            .get_attempt(action)
            .ip_addr(ip_addr)
            .jti(jti)
            .send()
            .await
            .context(Location::caller())?
        {
            let is_blocked = attempt.expired_at.unwrap_or(u64::MAX)
                > common::get_current_timestamp()
                    .call()
                    .context(Location::caller())?
                && attempt.attempt >= action.get_max_attempt();

            Ok(is_blocked)
        } else {
            Ok(false)
        }
    }

    #[optarg_method(AuthAttemptDbIncrBuilder, send)]
    pub async fn incr<'b, 'c>(
        &'b self,
        action: Action,
        #[optarg_default] ip_addr: &'c str,
        #[optarg_default] jti: &'c str,
        #[optarg(1)] attempt: u32,
        #[optarg_default] is_permanent: bool,
    ) -> Result<()> {
        let extend_by_in_minutes = if jti.is_empty() {
            60
        } else {
            action.get_jwt_token_validity_in_minutes()
        };

        let expired_at = common::extend_current_timestamp()
            .minutes(extend_by_in_minutes)
            .call()
            .context(Location::caller())?;

        let db_resp = self
            .dynamodb
            .update_item()
            .table_name(&*auth_constants::AUTH_ATTEMPT_TABLE_NAME)
            .key(
                "pk",
                AttributeValue::S(format!(
                    "{action}#{id}",
                    action = action.to_string().convert_snake_case_to_pascal_case(),
                    id = if !ip_addr.is_empty() {
                        ip_addr
                    } else if !jti.is_empty() {
                        jti
                    } else {
                        panic!("Unable to find id")
                    }
                )),
            )
            .key("sk", AttributeValue::S("Attempt".to_string()))
            .update_expression("SET attempt = attempt + :incr, expired_at = :ea")
            .condition_expression("attribute_exists(pk)")
            .expression_attribute_values(":incr", AttributeValue::N(attempt.to_string()))
            .expression_attribute_values(
                ":ea",
                if is_permanent {
                    AttributeValue::Null(true)
                } else {
                    AttributeValue::N(expired_at.to_string())
                },
            )
            .send()
            .await
            .context(Location::caller());

        if let Err(err) = db_resp {
            let err = err
                .downcast::<SdkError<_>>()
                .context(Location::caller())?
                .into_service_error();

            if let ConditionalCheckFailedException(_) = err {
                let attempt = AuthAttempt::new(action, attempt, expired_at)
                    .ip_addr(ip_addr)
                    .jti(jti)
                    .call();

                self.dynamodb
                    .put_item()
                    .table_name(&*auth_constants::AUTH_ATTEMPT_TABLE_NAME)
                    .set_item(Some(
                        serde_dynamo::to_item(attempt).context(Location::caller())?,
                    ))
                    .condition_expression("attribute_not_exists(pk)")
                    .send()
                    .await
                    .context(Location::caller())?;
            } else {
                return Err(Error::from(err).context(Location::caller()));
            }
        }

        Ok(())
    }
}
