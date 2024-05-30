use anyhow::{Context as _, Result};
use auth_lib::{
    auth_constants,
    auth_enums::{Action, UserAttr},
    auth_jwt::{AuthSessionToken, SessionTokenType},
    auth_user_context::AuthUserContext,
    AuthAttemptDb, AuthUserDb,
};
use aws_config::BehaviorVersion;
use aws_lambda_events::apigw::{ApiGatewayProxyRequest, ApiGatewayProxyResponse};
use common::{
    self,
    common_serde::Request,
    common_tracing::{self, Logger},
    ApiResponse,
};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use lambda_runtime::{run, service_fn, tracing::error, Context, Error, LambdaEvent};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::HashSet, panic::Location};
use uuid::Uuid;
use validator::Validate;

#[derive(Debug)]
struct Env {
    dynamodb: aws_sdk_dynamodb::Client,
    ssm: aws_sdk_ssm::Client,
    session_token_secret: String,
}

#[derive(Debug, PartialEq, Deserialize, Validate)]
struct HandlerRequest {
    attr: UserAttr,

    #[validate(length(min = 1))]
    code: String,
}

impl Request for HandlerRequest {}

#[derive(Debug, Default, PartialEq, Serialize)]
struct HandlerResponse {
    session_token: String,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    common_tracing::init();

    let config = aws_config::load_defaults(BehaviorVersion::latest()).await;
    let dynamodb = aws_sdk_dynamodb::Client::new(&config);
    let ssm = aws_sdk_ssm::Client::new(&config);

    let session_token_secret = ssm
        .get_parameter()
        .name(auth_constants::SESSION_TOKEN_PARAM_PATH)
        .with_decryption(true)
        .send()
        .await?
        .parameter
        .unwrap()
        .value
        .unwrap();

    let env = Env {
        dynamodb,
        ssm,
        session_token_secret,
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
        .is_blocked(Action::VerifyAttr)
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

    let user_db = AuthUserDb {
        dynamodb: &env.dynamodb,
        ssm: Some(&env.ssm),
    };

    let verification_code = user_db
        .get_verification_code(&user_ctx.sub)
        .await
        .context(Location::caller())?;

    if req.code != verification_code {
        let api_resp = ApiResponse {
            code: 4001,
            message: "Invalid code",
            request_id: &context.request_id,
            ..Default::default()
        };

        attempt_db
            .incr(Action::VerifyAttr)
            .jti(&*user_ctx.jti)
            .send()
            .await
            .context(Location::caller())?;

        return Ok(api_resp.into());
    }

    user_db
        .mark_attrs_as_verified(&user_ctx.name, HashSet::from_iter([UserAttr::EmailAddr]))
        .await
        .context(Location::caller())?;

    // Revoke this session token
    attempt_db
        .incr(Action::VerifyAttr)
        .jti(&*user_ctx.jti)
        .attempt(auth_constants::MAX_ACTION_ATTEMPT_MAP[&Action::VerifyAttr])
        .send()
        .await
        .context(Location::caller())?;

    let next_action = user_ctx.dest.unwrap();

    // Generate a new session token that is authorized to call init-mfa / reset-password / etc. API
    let session_token = jsonwebtoken::encode(
        &Header::new(Algorithm::HS512),
        &AuthSessionToken {
            typ: SessionTokenType::Session,
            jti: Uuid::new_v4().to_string(),
            exp: common::extend_current_timestamp()
                .minutes(auth_constants::JWT_TOKEN_VALIDITY_IN_MINUTES_MAP[&next_action])
                .call()
                .context(Location::caller())?,
            sub: user_ctx.sub,
            name: user_ctx.name,
            aud: next_action,
            dest: next_action,
        },
        &EncodingKey::from_secret(env.session_token_secret.as_ref()),
    )
    .context(Location::caller())?;

    let api_resp = ApiResponse {
        code: 2000,
        payload: serde_json::to_value(HandlerResponse { session_token })
            .context(Location::caller())?,
        request_id: &context.request_id,
        ..Default::default()
    };

    Ok(api_resp.into())
}
