use anyhow::{Context as _, Result};
use auth_lib::{
    auth_constants,
    auth_enums::{Action, UserAttr},
    auth_jwt::{AuthSessionToken, SessionTokenType},
    AuthAttemptDb, AuthUserContext, AuthUserDb,
};
use aws_config::BehaviorVersion;
use aws_lambda_events::apigw::{ApiGatewayProxyRequest, ApiGatewayProxyResponse};
use aws_sdk_ssm::types::Parameter;
use common::{
    self,
    common_serde::Request,
    common_tracing::{self, Logger},
    ApiResponse,
};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use lambda_runtime::{run, service_fn, tracing::error, Context, Error, LambdaEvent};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{collections::HashSet, mem, panic::Location};
use uuid::Uuid;
use validator::Validate;

#[derive(Debug)]
struct Env {
    dynamodb: aws_sdk_dynamodb::Client,
    ssm: aws_sdk_ssm::Client,
    session_token_secret: String,
    session_token_secret_version: u32,
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

    // Fetch the latest version of session token secret key
    let session_token_secret = mem::replace(
        ssm.get_parameters_by_path()
            .path(auth_constants::SESSION_TOKEN_PARAM_PATH)
            .with_decryption(true)
            .send()
            .await?
            .parameters
            .unwrap()
            .last_mut()
            .unwrap(),
        Parameter::builder().build(),
    );

    let env = Env {
        dynamodb,
        ssm,
        session_token_secret: session_token_secret.value.unwrap(),
        session_token_secret_version: session_token_secret
            .name
            .unwrap()
            .strip_prefix(&format!("{}/v", auth_constants::SESSION_TOKEN_PARAM_PATH))
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

    let user_id = user_ctx.sub.parse().context(Location::caller())?;
    let user_db = AuthUserDb::new(&env.dynamodb).ssm(&env.ssm).call();

    let verification_code = user_db
        .get_verification_code(user_id)
        .await
        .context(Location::caller())?;

    if req.code != verification_code {
        let api_resp = ApiResponse {
            code: 4001,
            message: "Invalid code".to_string(),
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

    // Revoke this session token
    let revoke_task = attempt_db
        .incr(Action::VerifyAttr)
        .jti(&*user_ctx.jti)
        .attempt(Action::VerifyAttr.get_max_attempt())
        .send();

    // Mark email address as verified by this user
    let mark_task =
        user_db.mark_attrs_as_verified(user_id, HashSet::from_iter([UserAttr::EmailAddr]));

    // Kickstart the DB related tasks
    let (revoke_task_resp, mark_task_resp) = tokio::join!(revoke_task, mark_task);
    revoke_task_resp.context(Location::caller())?;
    mark_task_resp.context(Location::caller())?;

    let next_action = user_ctx.dest.unwrap();

    // Generate a new session token that is authorized to call init-mfa / reset-password / etc. API
    let session_token = jsonwebtoken::encode(
        &Header::new(Algorithm::HS512),
        &AuthSessionToken {
            typ: SessionTokenType::Session,
            ver: env.session_token_secret_version,
            jti: Uuid::new_v4().to_string(),
            exp: common::extend_current_timestamp()
                .minutes(next_action.get_jwt_token_validity_in_minutes())
                .call()
                .context(Location::caller())?,
            sub: user_id,
            aud: next_action,
            dest: next_action,
        },
        &EncodingKey::from_secret(env.session_token_secret.as_ref()),
    )
    .context(Location::caller())?;

    let api_resp = ApiResponse {
        code: 2000,
        payload: json!(HandlerResponse { session_token }),
        request_id: &context.request_id,
        ..Default::default()
    };

    Ok(api_resp.into())
}
