#![deny(elided_lifetimes_in_paths)]

use anyhow::{Context as _, Result};
use auth_lib::{
    auth_constants,
    auth_enums::{Action, Role, UserAttr},
    auth_jwt::{AccessTokenType, AuthAccessToken, AuthRefreshToken, RefreshTokenType},
    AuthAttemptDb, AuthUserContext, AuthUserDb, AuthValidTokenPairDb,
};
use aws_config::BehaviorVersion;
use aws_lambda_events::apigw::{ApiGatewayProxyRequest, ApiGatewayProxyResponse};
use aws_sdk_ssm::types::Parameter;
use common::{
    common_serde::Request,
    common_tracing::{self, Logger},
    ApiResponse,
};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use lambda_runtime::{run, service_fn, tracing::error, Context, Error, LambdaEvent};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{collections::HashSet, mem, panic::Location};
use totp_rs::{Rfc6238, Secret, TOTP};
use uuid::Uuid;
use validator::Validate;

#[derive(Debug)]
struct Env {
    dynamodb: aws_sdk_dynamodb::Client,
    ssm: aws_sdk_ssm::Client,
    access_token_secret: String,
    access_token_secret_version: u32,
    refresh_token_secret: String,
    refresh_token_secret_version: u32,
}

#[derive(Debug, PartialEq, Deserialize, Validate)]
struct HandlerRequest {
    #[validate(length(min = 1))]
    code: String,
}

impl Request for HandlerRequest {}

#[derive(Debug, Default, PartialEq, Serialize)]
struct HandlerResponse {
    refresh_token: String,
    access_token: String,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    common_tracing::init();

    let config = aws_config::load_defaults(BehaviorVersion::latest()).await;
    let dynamodb = aws_sdk_dynamodb::Client::new(&config);
    let ssm = aws_sdk_ssm::Client::new(&config);

    let get_access_token_secret_task = ssm
        .get_parameters_by_path()
        .path(auth_constants::ACCESS_TOKEN_PARAM_PATH)
        .with_decryption(true)
        .send();

    let get_refresh_token_secret_task = ssm
        .get_parameters_by_path()
        .path(auth_constants::REFRESH_TOKEN_PARAM_PATH)
        .with_decryption(true)
        .send();

    // Kickstart the SSM related tasks
    let (get_access_token_secret_task_resp, get_refresh_token_secret_task_resp) =
        tokio::join!(get_access_token_secret_task, get_refresh_token_secret_task);

    // Fetch the latest version of access token secret key
    let access_token_secret = mem::replace(
        get_access_token_secret_task_resp?
            .parameters
            .unwrap()
            .last_mut()
            .unwrap(),
        Parameter::builder().build(),
    );

    // Fetch the latest version of refresh token secret key
    let refresh_token_secret = mem::replace(
        get_refresh_token_secret_task_resp?
            .parameters
            .unwrap()
            .last_mut()
            .unwrap(),
        Parameter::builder().build(),
    );

    let env = Env {
        dynamodb,
        ssm,
        access_token_secret: access_token_secret.value.unwrap(),
        access_token_secret_version: access_token_secret
            .name
            .unwrap()
            .strip_prefix(&format!("{}/v", auth_constants::ACCESS_TOKEN_PARAM_PATH))
            .unwrap()
            .parse()?,
        refresh_token_secret: refresh_token_secret.value.unwrap(),
        refresh_token_secret_version: refresh_token_secret
            .name
            .unwrap()
            .strip_prefix(&format!("{}/v", auth_constants::REFRESH_TOKEN_PARAM_PATH))
            .unwrap()
            .parse()?,
    };

    run(service_fn(
        |event: LambdaEvent<ApiGatewayProxyRequest>| async {
            let (event, context) = event.into_parts();

            match handler(event, &context, &env).await {
                Ok(resp) => Ok::<ApiGatewayProxyResponse, Error>(resp),
                Err(err) => {
                    error!("{err:?}");

                    let api_resp = ApiResponse {
                        code: 5000,
                        request_id: &context.request_id,
                        ..Default::default()
                    };

                    Ok(api_resp.into())
                }
            }
        },
    ))
    .await
}

async fn handler(
    mut event: ApiGatewayProxyRequest,
    context: &Context,
    env: &Env,
) -> Result<ApiGatewayProxyResponse> {
    if let Err(err) = event.log() {
        let api_resp = ApiResponse {
            code: 4000,
            message: err.to_string(),
            request_id: &context.request_id,
            ..Default::default()
        };

        return Ok(api_resp.into());
    }

    let req = match HandlerRequest::load(&event) {
        Ok(req) => req,
        Err(err) => {
            let api_resp = ApiResponse {
                code: 4001,
                message: err.to_string(),
                request_id: &context.request_id,
                ..Default::default()
            };

            return Ok(api_resp.into());
        }
    };

    let user_ctx: AuthUserContext =
        serde_json::from_value(Value::from_iter(event.request_context.authorizer.fields))
            .context(Location::caller())?;

    let src_action = user_ctx.src.unwrap();

    let attempt_db = AuthAttemptDb {
        dynamodb: &env.dynamodb,
    };

    if attempt_db
        .is_blocked(Action::VerifyMfa)
        .jti(&*user_ctx.jti)
        .send()
        .await
        .context(Location::caller())?
    {
        let api_resp = ApiResponse {
            code: 4030,
            request_id: &context.request_id,
            ..Default::default()
        };

        return Ok(api_resp.into());
    }

    let user_id = user_ctx.sub.parse().context(Location::caller())?;
    let mut user_db = AuthUserDb::new(&env.dynamodb).ssm(&env.ssm).call();

    let mfa_secret = user_db
        .get_mfa_secret(user_id)
        .await
        .context(Location::caller())?;

    if mfa_secret.is_empty() {
        let api_resp = ApiResponse {
            code: 4010,
            request_id: &context.request_id,
            ..Default::default()
        };

        attempt_db
            .incr(Action::VerifyMfa)
            .jti(&*user_ctx.jti)
            .send()
            .await
            .context(Location::caller())?;

        return Ok(api_resp.into());
    } else {
        let otp_code = TOTP::from_rfc6238(
            Rfc6238::with_defaults(
                Secret::Encoded(mfa_secret)
                    .to_bytes()
                    .context(Location::caller())?,
            )
            .context(Location::caller())?,
        )
        .context(Location::caller())?
        .generate_current()
        .context(Location::caller())?;

        if req.code != otp_code {
            let api_resp = ApiResponse {
                code: 4010,
                request_id: &context.request_id,
                ..Default::default()
            };

            attempt_db
                .incr(Action::VerifyMfa)
                .jti(&*user_ctx.jti)
                .send()
                .await
                .context(Location::caller())?;

            return Ok(api_resp.into());
        }
    }

    // Revoke this session token
    let revoke_task = attempt_db
        .incr(Action::VerifyMfa)
        .jti(&*user_ctx.jti)
        .attempt(Action::VerifyMfa.get_max_attempt())
        .send();

    let resp = match src_action {
        Action::InitMfa => {
            let mark_task =
                user_db.mark_attrs_as_verified(user_id, HashSet::from_iter([UserAttr::Mfa]));

            // Kickstart the DB related tasks
            let (revoke_task_resp, mark_task_resp) = tokio::join!(revoke_task, mark_task);
            revoke_task_resp.context(Location::caller())?;
            mark_task_resp.context(Location::caller())?;

            HandlerResponse::default()
        }
        Action::Login => {
            let valid_token_pair_db = AuthValidTokenPairDb {
                dynamodb: &env.dynamodb,
            };

            let refresh_token_jti = Uuid::new_v4().to_string();

            let refresh_token_exp = common::extend_current_timestamp()
                .days(1)
                .call()
                .context(Location::caller())?;

            let access_token_jti = Uuid::new_v4().to_string();

            let put_task = valid_token_pair_db.put_valid_token_pair(
                refresh_token_jti.to_string(),
                access_token_jti.to_string(),
                refresh_token_exp,
            );

            // Kickstart the DB related tasks
            let (revoke_task_resp, put_task_resp) = tokio::join!(revoke_task, put_task);
            revoke_task_resp.context(Location::caller())?;
            put_task_resp.context(Location::caller())?;

            let refresh_token = jsonwebtoken::encode(
                &Header::new(Algorithm::HS512),
                &AuthRefreshToken {
                    typ: RefreshTokenType::Refresh,
                    ver: env.refresh_token_secret_version,
                    jti: refresh_token_jti.to_string(),
                    sub: user_id,
                    exp: refresh_token_exp,
                    aud: Action::Refresh,
                },
                &EncodingKey::from_secret(env.refresh_token_secret.as_ref()),
            )
            .context(Location::caller())?;

            let access_token = jsonwebtoken::encode(
                &Header::new(Algorithm::HS512),
                &AuthAccessToken {
                    typ: AccessTokenType::Access,
                    ver: env.access_token_secret_version,
                    jti: access_token_jti,
                    exp: common::extend_current_timestamp()
                        .minutes(5)
                        .call()
                        .context(Location::caller())?,
                    sub: user_id,
                    roles: vec![Role::User],
                    orig: refresh_token_jti,
                },
                &EncodingKey::from_secret(env.access_token_secret.as_ref()),
            )
            .context(Location::caller())?;

            HandlerResponse {
                refresh_token,
                access_token,
            }
        }
        action => {
            panic!("Unexpected action '{action}' that issues session token to call verify-mfa API")
        }
    };

    let api_resp = ApiResponse {
        code: 2000,
        payload: json!(resp),
        request_id: &context.request_id,
        ..Default::default()
    };

    Ok(api_resp.into())
}
