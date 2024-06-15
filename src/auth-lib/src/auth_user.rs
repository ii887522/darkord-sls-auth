use crate::{
    auth_constants,
    auth_enums::{Locale, UserAttr},
};
use anyhow::{bail, Context, Error, Result};
use aws_sdk_dynamodb::{
    error::SdkError,
    operation::transact_write_items::TransactWriteItemsError::TransactionCanceledException,
    types::{
        AttributeValue, Put, ReturnValue, ReturnValuesOnConditionCheckFailure, TransactWriteItem,
    },
};
use common::{self, CommonError};
use magic_crypt::{new_magic_crypt, MagicCryptTrait};
use optarg2chain::optarg_impl;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::{collections::HashSet, panic::Location};

#[derive(
    Clone, Copy, Debug, Default, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize,
)]
enum Sk {
    #[default]
    User,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct AuthUser {
    pk: String,

    #[serde(default)]
    sk: Sk,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_id: Option<u32>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_user_id: Option<u32>,

    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub username: String,

    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub email_addr: String,

    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub password: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locale: Option<Locale>,

    #[serde(default, skip_serializing_if = "Map::is_empty")]
    pub extra: Map<String, Value>,

    #[serde(default, skip_serializing_if = "HashSet::is_empty")]
    pub verified_attrs: HashSet<UserAttr>,

    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub mfa_secret: String,

    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub verification_code: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code_expired_at: Option<u64>,
}

#[optarg_impl]
impl AuthUser {
    #[optarg_method(AuthUserNewBuilder, call)]
    fn new(
        #[optarg_default] user_id: Option<u32>,
        #[optarg_default] next_user_id: Option<u32>,
        #[optarg_default] username: String,
        #[optarg_default] email_addr: String,
        #[optarg_default] password: String,
        #[optarg_default] locale: Option<Locale>,
        #[optarg_default] extra: Map<String, Value>,
        #[optarg_default] verification_code: String,
        #[optarg_default] code_expired_at: Option<u64>,
    ) -> Self {
        Self {
            pk: if locale.is_some() {
                format!("UserId#{user_id}", user_id = user_id.unwrap())
            } else if !username.is_empty() {
                format!("Username#{username}")
            } else if !email_addr.is_empty() {
                format!("EmailAddr#{email_addr}")
            } else if next_user_id.is_some() {
                "NextUserId".to_string()
            } else {
                panic!("Unable to build pk")
            },
            sk: Sk::User,
            user_id,
            next_user_id,
            username,
            email_addr,
            password,
            locale,
            extra,
            verified_attrs: HashSet::new(),
            mfa_secret: "".to_string(),
            verification_code,
            code_expired_at,
        }
    }
}

#[derive(Debug)]
pub struct AuthUserDb<'a> {
    pub dynamodb: &'a aws_sdk_dynamodb::Client,
    pub ssm: Option<&'a aws_sdk_ssm::Client>,
}

impl<'a> AuthUserDb<'a> {
    pub async fn put_item(
        &'a self,
        username: String,
        email_addr: String,
        password: &str,
        locale: Locale,
        extra: Map<String, Value>,
        verification_code: String,
        code_expired_at: u64,
    ) -> Result<u32> {
        let db_resp = self
            .dynamodb
            .update_item()
            .table_name(&*auth_constants::AUTH_USER_TABLE_NAME)
            .key("pk", AttributeValue::S("NextUserId".to_string()))
            .key("sk", AttributeValue::S("User".to_string()))
            .return_values(ReturnValue::AllOld)
            .update_expression("SET next_user_id = next_user_id + :incr")
            .condition_expression("attribute_exists(pk)")
            .expression_attribute_values(":incr", AttributeValue::N("1".to_string()))
            .send()
            .await
            .context(Location::caller())?;

        let user_id = serde_dynamo::from_item::<_, AuthUser>(db_resp.attributes.unwrap())
            .context(Location::caller())?
            .next_user_id
            .unwrap();

        let pk_user_id_user = AuthUser::new()
            .user_id(user_id)
            .username(username.to_string())
            .email_addr(email_addr.to_string())
            .password(common::hash_secret(password))
            .locale(locale)
            .extra(extra)
            .verification_code(verification_code)
            .code_expired_at(code_expired_at)
            .call();

        let pk_username_user = AuthUser::new().user_id(user_id).username(username).call();

        let pk_email_addr_user = AuthUser::new()
            .user_id(user_id)
            .email_addr(email_addr)
            .call();

        let db_resp = self
            .dynamodb
            .transact_write_items()
            .transact_items(
                TransactWriteItem::builder()
                    .put(
                        Put::builder()
                            .table_name(&*auth_constants::AUTH_USER_TABLE_NAME)
                            .set_item(Some(
                                serde_dynamo::to_item(pk_user_id_user)
                                    .context(Location::caller())?,
                            ))
                            .condition_expression("attribute_not_exists(pk)")
                            .build()
                            .context(Location::caller())?,
                    )
                    .build(),
            )
            .transact_items(
                TransactWriteItem::builder()
                    .put(
                        Put::builder()
                            .table_name(&*auth_constants::AUTH_USER_TABLE_NAME)
                            .set_item(Some(
                                serde_dynamo::to_item(pk_username_user)
                                    .context(Location::caller())?,
                            ))
                            .condition_expression("attribute_not_exists(pk)")
                            .return_values_on_condition_check_failure(
                                ReturnValuesOnConditionCheckFailure::AllOld,
                            )
                            .build()
                            .context(Location::caller())?,
                    )
                    .build(),
            )
            .transact_items(
                TransactWriteItem::builder()
                    .put(
                        Put::builder()
                            .table_name(&*auth_constants::AUTH_USER_TABLE_NAME)
                            .set_item(Some(
                                serde_dynamo::to_item(pk_email_addr_user)
                                    .context(Location::caller())?,
                            ))
                            .condition_expression("attribute_not_exists(pk)")
                            .return_values_on_condition_check_failure(
                                ReturnValuesOnConditionCheckFailure::AllOld,
                            )
                            .build()
                            .context(Location::caller())?,
                    )
                    .build(),
            )
            .send()
            .await
            .context(Location::caller());

        if let Err(err) = db_resp {
            let err = err
                .downcast::<SdkError<_>>()
                .context(Location::caller())?
                .into_service_error();

            if let TransactionCanceledException(err) = err {
                for cancellation_reason in err.cancellation_reasons.unwrap_or_default() {
                    if cancellation_reason.code.unwrap_or_default() != "ConditionalCheckFailed" {
                        continue;
                    }

                    let item: AuthUser =
                        serde_dynamo::from_item(cancellation_reason.item.unwrap_or_default())
                            .context(Location::caller())?;

                    if item.pk.starts_with("Username#") {
                        let err = CommonError {
                            code: 4090,
                            message: "Username already exists",
                        };

                        bail!(err);
                    }

                    if item.pk.starts_with("EmailAddr#") {
                        let err = CommonError {
                            code: 4091,
                            message: "Email address already exists",
                        };

                        bail!(err);
                    }

                    panic!("Unhandled pk: {}", item.pk);
                }
            } else {
                return Err(Error::from(err).context(Location::caller()));
            }
        }

        Ok(user_id)
    }

    pub async fn get_verification_code(&'a self, user_id: u32) -> Result<String> {
        let db_resp = self
            .dynamodb
            .get_item()
            .table_name(&*auth_constants::AUTH_USER_TABLE_NAME)
            .key("pk", AttributeValue::S(format!("UserId#{user_id}")))
            .key("sk", AttributeValue::S("User".to_string()))
            .projection_expression("pk,verification_code,code_expired_at")
            .send()
            .await
            .context(Location::caller())?;

        if let Some(item) = db_resp.item {
            let user: AuthUser = serde_dynamo::from_item(item).context(Location::caller())?;

            if common::get_current_timestamp()
                .call()
                .context(Location::caller())?
                < user.code_expired_at.unwrap_or_default()
            {
                return Ok(user.verification_code);
            }
        }

        Ok("".to_string())
    }

    pub async fn mark_attrs_as_verified(
        &'a self,
        user_id: u32,
        attrs: HashSet<UserAttr>,
    ) -> Result<()> {
        self.dynamodb
            .update_item()
            .table_name(&*auth_constants::AUTH_USER_TABLE_NAME)
            .key("pk", AttributeValue::S(format!("UserId#{user_id}")))
            .key("sk", AttributeValue::S("User".to_string()))
            .update_expression("ADD verified_attrs :va")
            .condition_expression("attribute_exists(pk)")
            .expression_attribute_values(
                ":va",
                AttributeValue::Ss(
                    serde_dynamo::to_attribute_value::<_, AttributeValue>(attrs)
                        .context(Location::caller())?
                        .as_l()
                        .unwrap()
                        .iter()
                        .map(|user_attr| user_attr.as_s().unwrap().to_string())
                        .collect(),
                ),
            )
            .send()
            .await
            .context(Location::caller())?;

        Ok(())
    }

    pub async fn set_mfa_secret(&'a self, user_id: u32, mfa_secret: &str) -> Result<()> {
        let magic_crypt = new_magic_crypt!(
            self.ssm
                .unwrap()
                .get_parameter()
                .name(auth_constants::MFA_PARAM_PATH)
                .with_decryption(true)
                .send()
                .await
                .context(Location::caller())?
                .parameter
                .unwrap()
                .value
                .unwrap(),
            256
        );

        self.dynamodb
            .update_item()
            .table_name(&*auth_constants::AUTH_USER_TABLE_NAME)
            .key("pk", AttributeValue::S(format!("UserId#{user_id}")))
            .key("sk", AttributeValue::S("User".to_string()))
            .update_expression("SET mfa_secret = :ms")
            .condition_expression("attribute_exists(pk)")
            .expression_attribute_values(
                ":ms",
                AttributeValue::S(magic_crypt.encrypt_str_to_base64(mfa_secret)),
            )
            .send()
            .await
            .context(Location::caller())?;

        Ok(())
    }

    pub async fn get_item(&'a self, user_id: u32) -> Result<Option<AuthUser>> {
        let db_resp = self
            .dynamodb
            .get_item()
            .table_name(&*auth_constants::AUTH_USER_TABLE_NAME)
            .key("pk", AttributeValue::S(format!("UserId#{user_id}")))
            .key("sk", AttributeValue::S("User".to_string()))
            .projection_expression("pk,username,email_addr,password,verified_attrs")
            .send()
            .await
            .context(Location::caller())?;

        if let Some(item) = db_resp.item {
            let user: AuthUser = serde_dynamo::from_item(item).context(Location::caller())?;
            return Ok(Some(user));
        }

        Ok(None)
    }

    pub async fn get_mfa_secret(&'a self, user_id: u32) -> Result<String> {
        let db_resp = self
            .dynamodb
            .get_item()
            .table_name(&*auth_constants::AUTH_USER_TABLE_NAME)
            .key("pk", AttributeValue::S(format!("UserId#{user_id}")))
            .key("sk", AttributeValue::S("User".to_string()))
            .projection_expression("pk,mfa_secret")
            .send()
            .await
            .context(Location::caller())?;

        if let Some(item) = db_resp.item {
            let user: AuthUser = serde_dynamo::from_item(item).context(Location::caller())?;

            if !user.mfa_secret.is_empty() {
                let magic_crypt = new_magic_crypt!(
                    self.ssm
                        .unwrap()
                        .get_parameter()
                        .name(auth_constants::MFA_PARAM_PATH)
                        .with_decryption(true)
                        .send()
                        .await
                        .context(Location::caller())?
                        .parameter
                        .unwrap()
                        .value
                        .unwrap(),
                    256
                );

                let mfa_secret = magic_crypt
                    .decrypt_base64_to_string(user.mfa_secret)
                    .context(Location::caller())?;

                return Ok(mfa_secret);
            }
        }

        Ok("".to_string())
    }

    pub async fn get_user_id(&'a self, email_addr: &str) -> Result<Option<u32>> {
        let db_resp = self
            .dynamodb
            .get_item()
            .table_name(&*auth_constants::AUTH_USER_TABLE_NAME)
            .key("pk", AttributeValue::S(format!("EmailAddr#{email_addr}")))
            .key("sk", AttributeValue::S("User".to_string()))
            .projection_expression("pk,user_id")
            .send()
            .await
            .context(Location::caller())?;

        if let Some(item) = db_resp.item {
            let user: AuthUser = serde_dynamo::from_item(item).context(Location::caller())?;
            return Ok(user.user_id);
        }

        Ok(None)
    }

    pub async fn set_verification_code(
        &'a self,
        user_id: u32,
        verification_code: String,
    ) -> Result<()> {
        self.dynamodb
            .update_item()
            .table_name(&*auth_constants::AUTH_USER_TABLE_NAME)
            .key("pk", AttributeValue::S(format!("UserId#{user_id}")))
            .key("sk", AttributeValue::S("User".to_string()))
            .update_expression("SET verification_code = :vc, code_expired_at = :cea")
            .condition_expression("attribute_exists(pk)")
            .expression_attribute_values(":vc", AttributeValue::S(verification_code))
            .expression_attribute_values(
                ":cea",
                AttributeValue::N(
                    common::extend_current_timestamp()
                        .minutes(auth_constants::VERIFICATION_CODE_VALIDITY_IN_MINUTES)
                        .call()
                        .context(Location::caller())?
                        .to_string(),
                ),
            )
            .send()
            .await
            .context(Location::caller())?;

        Ok(())
    }

    pub async fn set_password(&'a self, user_id: u32, password: &str) -> Result<()> {
        self.dynamodb
            .update_item()
            .table_name(&*auth_constants::AUTH_USER_TABLE_NAME)
            .key("pk", AttributeValue::S(format!("UserId#{user_id}")))
            .key("sk", AttributeValue::S("User".to_string()))
            .update_expression("SET password = :p")
            .condition_expression("attribute_exists(pk)")
            .expression_attribute_values(":p", AttributeValue::S(common::hash_secret(password)))
            .send()
            .await
            .context(Location::caller())?;

        Ok(())
    }
}
