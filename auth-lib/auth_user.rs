use crate::{
    auth_constants,
    auth_enums::{Locale, UserAttr},
};
use anyhow::{bail, Context, Error, Result};
use aws_sdk_dynamodb::{
    error::SdkError,
    operation::transact_write_items::TransactWriteItemsError::TransactionCanceledException,
    operation::update_item::UpdateItemError::ConditionalCheckFailedException,
    types::{
        AttributeValue, Put, ReturnValue, ReturnValuesOnConditionCheckFailure, TransactWriteItem,
    },
};
use common::CommonError;
use magic_crypt::{new_magic_crypt, MagicCrypt256, MagicCryptTrait};
use optarg2chain::optarg_impl;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::{
    collections::{hash_map::Entry, HashMap, HashSet},
    panic::Location,
};

#[derive(
    Clone, Copy, Debug, Default, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize,
)]
enum Sk {
    #[default]
    User,
}

#[derive(
    Clone, Copy, Debug, Default, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize,
)]
enum DetailSk {
    #[default]
    Detail,
}

#[derive(
    Clone, Copy, Debug, Default, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize,
)]
enum VerificationSk {
    #[default]
    Verification,
}

#[derive(
    Clone, Copy, Debug, Default, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize,
)]
enum MfaSk {
    #[default]
    Mfa,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct AuthUser {
    pk: String,

    #[serde(default)]
    sk: Sk,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_id: Option<u32>,

    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub username: String,

    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub email_addr: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_user_id: Option<u32>,
}

#[optarg_impl]
impl AuthUser {
    #[optarg_method(AuthUserNewBuilder, call)]
    fn new(
        #[optarg_default] user_id: Option<u32>,
        #[optarg_default] username: String,
        #[optarg_default] email_addr: String,
        #[optarg_default] next_user_id: Option<u32>,
    ) -> Self {
        Self {
            pk: if !username.is_empty() {
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
            username,
            email_addr,
            next_user_id,
        }
    }
}

#[derive(Debug, Default, PartialEq)]
pub struct AuthUserAll {
    pub detail: Option<AuthUserDetail>,
    pub verification: Option<AuthUserVerification>,
    pub mfa: Option<AuthUserMfa>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct AuthUserDetail {
    pk: String,

    #[serde(default)]
    sk: DetailSk,

    pub user_id: u32,
    pub username: String,
    pub email_addr: String,
    pub password: String,
    pub locale: Locale,

    #[serde(default, skip_serializing_if = "Map::is_empty")]
    pub extra: Map<String, Value>,

    #[serde(default, skip_serializing_if = "HashSet::is_empty")]
    pub verified_attrs: HashSet<UserAttr>,
}

impl AuthUserDetail {
    fn new(
        user_id: u32,
        username: String,
        email_addr: String,
        password: String,
        locale: Locale,
        extra: Map<String, Value>,
    ) -> Self {
        Self {
            pk: format!("User#{user_id}"),
            sk: DetailSk::Detail,
            user_id,
            username,
            email_addr,
            password,
            locale,
            extra,
            verified_attrs: HashSet::new(),
        }
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct AuthUserVerification {
    pk: String,

    #[serde(default)]
    sk: VerificationSk,

    pub user_id: u32,
    pub verification_code: String,
    pub expired_at: u64,
}

impl AuthUserVerification {
    fn new(user_id: u32, verification_code: String, expired_at: u64) -> Self {
        Self {
            pk: format!("User#{user_id}"),
            sk: VerificationSk::Verification,
            user_id,
            verification_code,
            expired_at,
        }
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct AuthUserMfa {
    pk: String,

    #[serde(default)]
    sk: MfaSk,

    pub user_id: u32,
    pub secret: String,
    pub version: u32,
}

impl AuthUserMfa {
    fn new(user_id: u32, secret: String, version: u32) -> Self {
        Self {
            pk: format!("User#{user_id}"),
            sk: MfaSk::Mfa,
            user_id,
            secret,
            version,
        }
    }
}

#[derive(Debug)]
pub struct AuthUserDb<'a> {
    dynamodb: &'a aws_sdk_dynamodb::Client,
    ssm: Option<&'a aws_sdk_ssm::Client>,
    mfa_secret_key: Option<&'a MagicCrypt256>,
    mfa_secret_version: u32,
    mfa_secret_key_cache: HashMap<u32, MagicCrypt256>,
}

#[optarg_impl]
impl<'a> AuthUserDb<'a> {
    #[optarg_method(AuthUserDbNewBuilder, call)]
    pub fn new(
        dynamodb: &'a aws_sdk_dynamodb::Client,
        #[optarg_default] ssm: Option<&'a aws_sdk_ssm::Client>,
        #[optarg_default] mfa_secret_key: Option<&'a MagicCrypt256>,
        #[optarg_default] mfa_secret_version: u32,
    ) -> Self {
        Self {
            dynamodb,
            ssm,
            mfa_secret_key,
            mfa_secret_version,
            mfa_secret_key_cache: HashMap::new(),
        }
    }

    pub async fn put_all(
        &self,
        username: String,
        email_addr: String,
        password: String,
        locale: Locale,
        extra: Map<String, Value>,
        verification_code: String,
        code_expired_at: u64,
    ) -> Result<u32> {
        let db_resp = auth_constants::AUTH_USER_TABLE_NAME
            .with(|user_table_name| {
                self.dynamodb
                    .update_item()
                    .table_name(user_table_name)
                    .key("pk", AttributeValue::S("NextUserId".to_string()))
                    .key("sk", AttributeValue::S("User".to_string()))
                    .return_values(ReturnValue::AllOld)
                    .update_expression("SET next_user_id = next_user_id + :incr")
                    .condition_expression("attribute_exists(pk)")
                    .expression_attribute_values(":incr", AttributeValue::N(1.to_string()))
                    .send()
            })
            .await
            .context(Location::caller())?;

        let user = serde_dynamo::from_item::<_, AuthUser>(db_resp.attributes.unwrap())
            .context(Location::caller())?;

        let user_id = user.next_user_id.unwrap();

        let user_detail = AuthUserDetail::new(
            user_id,
            username.to_string(),
            email_addr.to_string(),
            common::hash_secret(&password),
            locale,
            extra,
        );

        let user_verification =
            AuthUserVerification::new(user_id, verification_code, code_expired_at);

        let pk_username_user = AuthUser::new().user_id(user_id).username(username).call();

        let pk_email_addr_user = AuthUser::new()
            .user_id(user_id)
            .email_addr(email_addr)
            .call();

        let raw_user_detail = serde_dynamo::to_item(user_detail).context(Location::caller())?;

        let raw_user_verification =
            serde_dynamo::to_item(user_verification).context(Location::caller())?;

        let raw_pk_username_user =
            serde_dynamo::to_item(pk_username_user).context(Location::caller())?;

        let raw_pk_email_addr_user =
            serde_dynamo::to_item(pk_email_addr_user).context(Location::caller())?;

        let db_resp = self
            .dynamodb
            .transact_write_items()
            .transact_items(
                TransactWriteItem::builder()
                    .put(
                        auth_constants::AUTH_USER_TABLE_NAME
                            .with(|user_table_name| {
                                Put::builder()
                                    .table_name(user_table_name)
                                    .set_item(Some(raw_user_detail))
                                    .condition_expression("attribute_not_exists(pk)")
                                    .build()
                            })
                            .context(Location::caller())?,
                    )
                    .build(),
            )
            .transact_items(
                TransactWriteItem::builder()
                    .put(
                        auth_constants::AUTH_USER_TABLE_NAME
                            .with(|user_table_name| {
                                Put::builder()
                                    .table_name(user_table_name)
                                    .set_item(Some(raw_user_verification))
                                    .condition_expression("attribute_not_exists(pk)")
                                    .build()
                            })
                            .context(Location::caller())?,
                    )
                    .build(),
            )
            .transact_items(
                TransactWriteItem::builder()
                    .put(
                        auth_constants::AUTH_USER_TABLE_NAME
                            .with(|user_table_name| {
                                Put::builder()
                                    .table_name(user_table_name)
                                    .set_item(Some(raw_pk_username_user))
                                    .condition_expression("attribute_not_exists(pk)")
                                    .return_values_on_condition_check_failure(
                                        ReturnValuesOnConditionCheckFailure::AllOld,
                                    )
                                    .build()
                            })
                            .context(Location::caller())?,
                    )
                    .build(),
            )
            .transact_items(
                TransactWriteItem::builder()
                    .put(
                        auth_constants::AUTH_USER_TABLE_NAME
                            .with(|user_table_name| {
                                Put::builder()
                                    .table_name(user_table_name)
                                    .set_item(Some(raw_pk_email_addr_user))
                                    .condition_expression("attribute_not_exists(pk)")
                                    .return_values_on_condition_check_failure(
                                        ReturnValuesOnConditionCheckFailure::AllOld,
                                    )
                                    .build()
                            })
                            .context(Location::caller())?,
                    )
                    .build(),
            )
            .send()
            .await
            .context(Location::caller());

        let Err(err) = db_resp else {
            return Ok(user_id);
        };

        let mut err = err
            .downcast::<SdkError<_>>()
            .context(Location::caller())?
            .into_service_error();

        if let TransactionCanceledException(err) = &mut err {
            for cancellation_reason in err.cancellation_reasons.as_mut().unwrap_or(&mut vec![]) {
                let Some(reason_code) = cancellation_reason.code.as_ref() else {
                    continue;
                };

                if reason_code != "ConditionalCheckFailed" && reason_code != "TransactionConflict" {
                    continue;
                }

                let user: AuthUser =
                    serde_dynamo::from_item(cancellation_reason.item.take().unwrap_or_default())
                        .context(Location::caller())?;

                if user.pk.starts_with("Username#") {
                    let err = CommonError {
                        code: 4090,
                        message: "Username already exists".to_string(),
                    };

                    bail!(err);
                }

                if user.pk.starts_with("EmailAddr#") {
                    let err = CommonError {
                        code: 4091,
                        message: "Email address already exists".to_string(),
                    };

                    bail!(err);
                }

                panic!("Unhandled pk: {}", user.pk);
            }
        }

        Err(Error::from(err).context(Location::caller()))
    }

    pub async fn get_verification_code(&self, user_id: u32) -> Result<String> {
        let db_resp = auth_constants::AUTH_USER_TABLE_NAME
            .with(|user_table_name| {
                self.dynamodb
                    .get_item()
                    .table_name(user_table_name)
                    .key("pk", AttributeValue::S(format!("User#{user_id}")))
                    .key("sk", AttributeValue::S("Verification".to_string()))
                    .projection_expression("pk,user_id,verification_code,expired_at")
                    .send()
            })
            .await
            .context(Location::caller())?;

        let Some(item) = db_resp.item else {
            return Ok("".to_string());
        };

        let user_verification: AuthUserVerification =
            serde_dynamo::from_item(item).context(Location::caller())?;

        let now = common::get_current_timestamp()
            .call()
            .context(Location::caller())?;

        if now >= user_verification.expired_at {
            return Ok("".to_string());
        }

        Ok(user_verification.verification_code)
    }

    pub async fn mark_attrs_as_verified(
        &self,
        user_id: u32,
        attrs: HashSet<UserAttr>,
    ) -> Result<()> {
        let raw_attrs = serde_dynamo::to_attribute_value::<_, AttributeValue>(attrs)
            .context(Location::caller())?
            .as_l()
            .unwrap()
            .iter()
            .map(|user_attr| user_attr.as_s().unwrap().to_string())
            .collect();

        auth_constants::AUTH_USER_TABLE_NAME
            .with(|user_table_name| {
                self.dynamodb
                    .update_item()
                    .table_name(user_table_name)
                    .key("pk", AttributeValue::S(format!("User#{user_id}")))
                    .key("sk", AttributeValue::S("Detail".to_string()))
                    .update_expression("ADD verified_attrs :va")
                    .condition_expression("attribute_exists(pk)")
                    .expression_attribute_values(":va", AttributeValue::Ss(raw_attrs))
                    .send()
            })
            .await
            .context(Location::caller())?;

        Ok(())
    }

    #[optarg_method(AuthUserDbSetMfaSecretBuilder, send)]
    pub async fn set_mfa_secret<'b, 'c>(
        &'b self,
        user_id: u32,
        mfa_secret: &'c str,
        #[optarg_default] expected_mfa_secret_version: u32,
    ) -> Result<()> {
        if expected_mfa_secret_version != 0
            && self.mfa_secret_version != expected_mfa_secret_version
        {
            let err = CommonError {
                code: 5000,
                message: format!(
                    "mfa_secret_version is outdated. Expect: {expected_mfa_secret_version}, Actual: {mfa_secret_version}",
                    mfa_secret_version = self.mfa_secret_version
                ),
            };

            bail!(err);
        }

        let encrypted_mfa_secret = self
            .mfa_secret_key
            .unwrap()
            .encrypt_str_to_base64(mfa_secret);

        let db_resp = auth_constants::AUTH_USER_TABLE_NAME
            .with(|user_table_name| {
                self.dynamodb
                    .update_item()
                    .table_name(user_table_name)
                    .key("pk", AttributeValue::S(format!("User#{user_id}")))
                    .key("sk", AttributeValue::S("Mfa".to_string()))
                    .update_expression("SET secret = :s, version = :v")
                    .condition_expression("attribute_exists(pk)")
                    .expression_attribute_values(
                        ":s",
                        AttributeValue::S(encrypted_mfa_secret.to_string()),
                    )
                    .expression_attribute_values(
                        ":v",
                        AttributeValue::N(self.mfa_secret_version.to_string()),
                    )
                    .send()
            })
            .await
            .context(Location::caller());

        let Err(err) = db_resp else {
            return Ok(());
        };

        let err = err
            .downcast::<SdkError<_>>()
            .context(Location::caller())?
            .into_service_error();

        if let ConditionalCheckFailedException(_) = err {
            let user_mfa = AuthUserMfa::new(user_id, encrypted_mfa_secret, self.mfa_secret_version);
            let raw_user_mfa = serde_dynamo::to_item(user_mfa).context(Location::caller())?;

            auth_constants::AUTH_USER_TABLE_NAME
                .with(|user_table_name| {
                    self.dynamodb
                        .put_item()
                        .table_name(user_table_name)
                        .set_item(Some(raw_user_mfa))
                        .condition_expression("attribute_not_exists(pk)")
                        .send()
                })
                .await
                .context(Location::caller())?;

            Ok(())
        } else {
            Err(Error::from(err).context(Location::caller()))
        }
    }

    pub async fn get_detail(&self, user_id: u32) -> Result<Option<AuthUserDetail>> {
        let db_resp = auth_constants::AUTH_USER_TABLE_NAME
            .with(|user_table_name| {
                self.dynamodb
                    .get_item()
                    .table_name(user_table_name)
                    .key("pk", AttributeValue::S(format!("User#{user_id}")))
                    .key("sk", AttributeValue::S("Detail".to_string()))
                    .projection_expression(
                        "pk,user_id,username,email_addr,password,locale,verified_attrs",
                    )
                    .send()
            })
            .await
            .context(Location::caller())?;

        db_resp.item.map_or(Ok(None), |item| {
            serde_dynamo::from_item(item).context(Location::caller())
        })
    }

    pub async fn get_mfa_secret(&mut self, user_id: u32) -> Result<String> {
        let db_resp = auth_constants::AUTH_USER_TABLE_NAME
            .with(|user_table_name| {
                self.dynamodb
                    .get_item()
                    .table_name(user_table_name)
                    .key("pk", AttributeValue::S(format!("User#{user_id}")))
                    .key("sk", AttributeValue::S("Mfa".to_string()))
                    .projection_expression("pk,user_id,secret,version")
                    .send()
            })
            .await
            .context(Location::caller())?;

        let Some(item) = db_resp.item else {
            return Ok("".to_string());
        };

        let user_mfa: AuthUserMfa = serde_dynamo::from_item(item).context(Location::caller())?;

        if let Entry::Vacant(entry) = self.mfa_secret_key_cache.entry(user_mfa.version) {
            let mfa_secret_key = new_magic_crypt!(
                self.ssm
                    .unwrap()
                    .get_parameter()
                    .name(format!(
                        "{name}/v{version:0>3}",
                        name = auth_constants::MFA_PARAM_PATH,
                        version = user_mfa.version
                    ))
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

            entry.insert(mfa_secret_key);
        };

        let mfa_secret = self.mfa_secret_key_cache[&user_mfa.version]
            .decrypt_base64_to_string(user_mfa.secret)
            .context(Location::caller())?;

        Ok(mfa_secret)
    }

    pub async fn get_user_id(&self, email_addr: &str) -> Result<Option<u32>> {
        let db_resp = auth_constants::AUTH_USER_TABLE_NAME
            .with(|user_table_name| {
                self.dynamodb
                    .get_item()
                    .table_name(user_table_name)
                    .key("pk", AttributeValue::S(format!("EmailAddr#{email_addr}")))
                    .key("sk", AttributeValue::S("User".to_string()))
                    .projection_expression("pk,user_id")
                    .send()
            })
            .await
            .context(Location::caller())?;

        db_resp.item.map_or(Ok(None), |item| {
            serde_dynamo::from_item(item)
                .context(Location::caller())
                .map(|user: AuthUser| user.user_id)
        })
    }

    pub async fn set_verification_code(
        &self,
        user_id: u32,
        verification_code: String,
    ) -> Result<()> {
        let expired_at = common::extend_current_timestamp()
            .minutes(auth_constants::VERIFICATION_CODE_VALIDITY_IN_MINUTES)
            .call()
            .context(Location::caller())?;

        let db_resp = auth_constants::AUTH_USER_TABLE_NAME
            .with(|user_table_name| {
                self.dynamodb
                    .update_item()
                    .table_name(user_table_name)
                    .key("pk", AttributeValue::S(format!("User#{user_id}")))
                    .key("sk", AttributeValue::S("Verification".to_string()))
                    .update_expression("SET verification_code = :vc, expired_at = :ea")
                    .condition_expression("attribute_exists(pk)")
                    .expression_attribute_values(
                        ":vc",
                        AttributeValue::S(verification_code.to_string()),
                    )
                    .expression_attribute_values(":ea", AttributeValue::N(expired_at.to_string()))
                    .send()
            })
            .await
            .context(Location::caller());

        let Err(err) = db_resp else {
            return Ok(());
        };

        let err = err
            .downcast::<SdkError<_>>()
            .context(Location::caller())?
            .into_service_error();

        if let ConditionalCheckFailedException(_) = err {
            let user_verification =
                AuthUserVerification::new(user_id, verification_code, expired_at);

            let raw_user_verification =
                serde_dynamo::to_item(user_verification).context(Location::caller())?;

            auth_constants::AUTH_USER_TABLE_NAME
                .with(|user_table_name| {
                    self.dynamodb
                        .put_item()
                        .table_name(user_table_name)
                        .set_item(Some(raw_user_verification))
                        .condition_expression("attribute_not_exists(pk)")
                        .send()
                })
                .await
                .context(Location::caller())?;

            Ok(())
        } else {
            Err(Error::from(err).context(Location::caller()))
        }
    }

    pub async fn set_password(&self, user_id: u32, password: &str) -> Result<()> {
        auth_constants::AUTH_USER_TABLE_NAME
            .with(|user_table_name| {
                self.dynamodb
                    .update_item()
                    .table_name(user_table_name)
                    .key("pk", AttributeValue::S(format!("User#{user_id}")))
                    .key("sk", AttributeValue::S("Detail".to_string()))
                    .update_expression("SET password = :p")
                    .condition_expression("attribute_exists(pk)")
                    .expression_attribute_values(
                        ":p",
                        AttributeValue::S(common::hash_secret(password)),
                    )
                    .send()
            })
            .await
            .context(Location::caller())?;

        Ok(())
    }

    pub async fn rotate_mfa_secret(&mut self, user_id: u32) -> Result<()> {
        let mfa_secret = self
            .get_mfa_secret(user_id)
            .await
            .context(Location::caller())?;

        if mfa_secret.is_empty() {
            return Ok(());
        }

        self.set_mfa_secret(user_id, &mfa_secret)
            .send()
            .await
            .context(Location::caller())
    }

    pub async fn get_next_user_id(&self) -> Result<u32> {
        let db_resp = auth_constants::AUTH_USER_TABLE_NAME
            .with(|user_table_name| {
                self.dynamodb
                    .get_item()
                    .table_name(user_table_name)
                    .key("pk", AttributeValue::S("NextUserId".to_string()))
                    .key("sk", AttributeValue::S("User".to_string()))
                    .projection_expression("pk,next_user_id")
                    .send()
            })
            .await
            .context(Location::caller())?;

        db_resp.item.map_or(Ok(0), |item| {
            serde_dynamo::from_item(item)
                .context(Location::caller())
                .map(|user: AuthUser| user.next_user_id.unwrap_or_default())
        })
    }

    pub async fn get_all(&self, user_id: u32) -> Result<Option<AuthUserAll>> {
        let db_resp = auth_constants::AUTH_USER_TABLE_NAME
            .with(|user_table_name| {
                self.dynamodb
                    .query()
                    .table_name(user_table_name)
                    .key_condition_expression("pk = :pk")
                    .expression_attribute_values(
                        ":pk",
                        AttributeValue::S(format!("User#{user_id}")),
                    )
                    .send()
            })
            .await
            .context(Location::caller())?;

        db_resp.items.map_or(Ok(None), |items| {
            let mut user_all = AuthUserAll::default();

            for item in items {
                if item["sk"] == AttributeValue::S("Detail".to_string()) {
                    user_all.detail =
                        Some(serde_dynamo::from_item(item).context(Location::caller())?);
                } else if item["sk"] == AttributeValue::S("Verification".to_string()) {
                    user_all.verification =
                        Some(serde_dynamo::from_item(item).context(Location::caller())?);
                } else if item["sk"] == AttributeValue::S("Mfa".to_string()) {
                    user_all.mfa = Some(serde_dynamo::from_item(item).context(Location::caller())?);
                }
            }

            Ok(Some(user_all))
        })
    }
}
