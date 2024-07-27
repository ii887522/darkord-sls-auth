use crate::{auth_constants, auth_enums::Role};
use anyhow::{Context, Result};
use aws_sdk_dynamodb::types::AttributeValue;
use common::common_enums::Method;
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, panic::Location};

#[derive(
    Clone, Copy, Debug, Default, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize,
)]
enum Sk {
    #[default]
    Rbac,
}

#[derive(Debug, PartialEq, Deserialize)]
pub struct AuthRbac {
    pk: String,
    sk: Sk,
    pub method: Method,
    pub path: String,
    pub roles: HashSet<Role>,
}

// For Lambda use only
#[derive(Debug, PartialEq)]
pub struct AuthRbacExt {
    pub rbac: Option<AuthRbac>,
    pub expired_at: u64,
}

#[derive(Debug)]
pub struct AuthRbacDb<'a> {
    pub dynamodb: &'a aws_sdk_dynamodb::Client,
}

impl<'a> AuthRbacDb<'a> {
    pub async fn get_rbac(&self, method: &str, path: &str) -> Result<Option<AuthRbac>> {
        let db_resp = self
            .dynamodb
            .get_item()
            .table_name(&*auth_constants::AUTH_RBAC_TABLE_NAME)
            .key("pk", AttributeValue::S(format!("Route#{method}_/{path}")))
            .key("sk", AttributeValue::S("Rbac".to_string()))
            .send()
            .await
            .context(Location::caller())?;

        db_resp.item.map_or(Ok(None), |item| {
            serde_dynamo::from_item(item).context(Location::caller())
        })
    }
}
