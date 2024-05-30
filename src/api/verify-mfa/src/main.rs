use anyhow::{Context as _, Result};
use auth_lib::{
    auth_constants,
    auth_enums::{Action, Role},
    auth_jwt::{AccessTokenType, AuthAccessToken, AuthRefreshToken, RefreshTokenType},
    auth_user_context::AuthUserContext,
    AuthAttemptDb, AuthUserDb, AuthValidTokenPairDb,
};
use aws_config::BehaviorVersion;
use aws_lambda_events::apigw::{ApiGatewayProxyRequest, ApiGatewayProxyResponse};
use common::{
    common_serde::Request,
    common_tracing::{self, Logger},
    ApiResponse,
};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use lambda_runtime::{run, service_fn, tracing::error, Context, Error, LambdaEvent};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::panic::Location;
use totp_rs::{Rfc6238, Secret, TOTP};
use uuid::Uuid;
use validator::Validate;

#[derive(Debug)]
struct Env {
    dynamodb: aws_sdk_dynamodb::Client,
    ssm: aws_sdk_ssm::Client,
    access_token_secret: String,
    refresh_token_secret: String,
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

    let [access_token_secret, refresh_token_secret, _] = ssm
        .get_parameters_by_path()
        .path(auth_constants::JWT_TOKEN_PARAM_PATH)
        .recursive(false)
        .with_decryption(true)
        .send()
        .await?
        .parameters
        .unwrap()
        .try_into()
        .unwrap();

    let env = Env {
        dynamodb,
        ssm,
        access_token_secret: access_token_secret.value.unwrap(),
        refresh_token_secret: refresh_token_secret.value.unwrap(),
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
            message: &err.to_string(),
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
                message: &err.to_string(),
                request_id: &context.request_id,
                ..Default::default()
            };

            return Ok(api_resp.into());
        }
    };

    let user_ctx: AuthUserContext =
        serde_json::from_value(Value::from_iter(event.request_context.authorizer.fields))
            .context(Location::caller())?;

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

    let mfa_secret = AuthUserDb {
        dynamodb: &env.dynamodb,
        ssm: Some(&env.ssm),
    }
    .get_mfa_secret(&user_ctx.name)
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
    attempt_db
        .incr(Action::VerifyMfa)
        .jti(&*user_ctx.jti)
        .attempt(auth_constants::MAX_ACTION_ATTEMPT_MAP[&Action::VerifyMfa])
        .send()
        .await
        .context(Location::caller())?;

    let refresh_token_jti = Uuid::new_v4().to_string();

    let refresh_token_exp = common::extend_current_timestamp()
        .days(1u64)
        .call()
        .context(Location::caller())?;

    let refresh_token = jsonwebtoken::encode(
        &Header::new(Algorithm::HS512),
        &AuthRefreshToken {
            typ: RefreshTokenType::Refresh,
            jti: refresh_token_jti.to_string(),
            exp: refresh_token_exp,
            aud: Action::Refresh,
        },
        &EncodingKey::from_secret(env.refresh_token_secret.as_ref()),
    )
    .context(Location::caller())?;

    let access_token_jti = Uuid::new_v4().to_string();

    let access_token = jsonwebtoken::encode(
        &Header::new(Algorithm::HS512),
        &AuthAccessToken {
            typ: AccessTokenType::Access,
            jti: access_token_jti.to_string(),
            exp: common::extend_current_timestamp()
                .minutes(5u64)
                .call()
                .context(Location::caller())?,
            sub: user_ctx.sub,
            name: user_ctx.name,
            roles: vec![Role::User],
            orig: refresh_token_jti.to_string(),
        },
        &EncodingKey::from_secret(env.access_token_secret.as_ref()),
    )
    .context(Location::caller())?;

    AuthValidTokenPairDb {
        dynamodb: &env.dynamodb,
    }
    .put_item(refresh_token_jti, access_token_jti, refresh_token_exp)
    .await
    .context(Location::caller())?;

    let resp = HandlerResponse {
        refresh_token,
        access_token,
    };

    let api_resp = ApiResponse {
        code: 2000,
        payload: serde_json::to_value(resp).context(Location::caller())?,
        request_id: &context.request_id,
        ..Default::default()
    };

    Ok(api_resp.into())
}
