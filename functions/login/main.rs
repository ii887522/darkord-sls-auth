use anyhow::{Context as _, Result};
use auth_lib::{
    auth_constants,
    auth_enums::{Action, UserAttr},
    auth_jwt::{AuthSessionToken, SessionTokenType},
    AuthAttemptDb, AuthUserDb,
};
use aws_config::BehaviorVersion;
use aws_lambda_events::apigw::{ApiGatewayProxyRequest, ApiGatewayProxyResponse};
use aws_sdk_ssm::types::Parameter;
use common::{
    self,
    common_serde::Request,
    common_tracing::{self, Logger},
    ApiResponse, TrimmedString,
};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use lambda_runtime::{run, service_fn, tracing::error, Context, Error, LambdaEvent};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{mem, panic::Location};
use uuid::Uuid;
use validator::Validate;

#[derive(Debug)]
struct Env {
    dynamodb: aws_sdk_dynamodb::Client,
    session_token_secret: String,
    session_token_secret_version: u32,
}

#[derive(Debug, PartialEq, Deserialize, Validate)]
struct HandlerRequest {
    #[validate(email, length(min = 1))]
    email_addr: TrimmedString,

    #[validate(length(min = 1))]
    password: String,
}

impl Request for HandlerRequest {}

#[derive(Debug, Default, PartialEq, Serialize)]
struct HandlerResponse {
    session_token: String,
    verification_code: String, // todo: Only for testing purpose. To be removed
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

    let ip_addr = event.request_context.identity.source_ip.as_ref();

    let attempt_db = AuthAttemptDb {
        dynamodb: &env.dynamodb,
    };

    if attempt_db
        .is_blocked(Action::Login)
        .ip_addr(&**ip_addr.unwrap_or(&"".to_string()))
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

    let user_db = AuthUserDb::new(&env.dynamodb).call();

    let Some(user_id) = user_db
        .get_user_id(&req.email_addr)
        .await
        .context(Location::caller())?
    else {
        let api_resp = ApiResponse {
            code: 4010,
            request_id: &context.request_id,
            ..Default::default()
        };

        attempt_db
            .incr(Action::Login)
            .ip_addr(&**ip_addr.unwrap_or(&"".to_string()))
            .send()
            .await
            .context(Location::caller())?;

        return Ok(api_resp.into());
    };

    let Some(user_all) = user_db.get_all(user_id).await.context(Location::caller())? else {
        let api_resp = ApiResponse {
            code: 4010,
            request_id: &context.request_id,
            ..Default::default()
        };

        attempt_db
            .incr(Action::Login)
            .ip_addr(&**ip_addr.unwrap_or(&"".to_string()))
            .send()
            .await
            .context(Location::caller())?;

        return Ok(api_resp.into());
    };

    let user_detail = user_all.detail.unwrap();
    let user_mfa = user_all.mfa;

    if !common::verify_secret(&req.password, &user_detail.password) {
        let api_resp = ApiResponse {
            code: 4010,
            request_id: &context.request_id,
            ..Default::default()
        };

        attempt_db
            .incr(Action::Login)
            .ip_addr(&**ip_addr.unwrap_or(&"".to_string()))
            .send()
            .await
            .context(Location::caller())?;

        return Ok(api_resp.into());
    }

    // User hasn't verified their email address
    let resp = if !user_detail.verified_attrs.contains(&UserAttr::EmailAddr) {
        let verification_code = common::gen_secret_digits().call();

        user_db
            .set_verification_code(user_id, verification_code.to_string())
            .await
            .context(Location::caller())?;

        // todo: Send a verification email to the given email address with the verification code
        // todo: Email content based on the given locale

        // Generate a new session token that is authorized to call verify-email API
        let session_token = jsonwebtoken::encode(
            &Header::new(Algorithm::HS512),
            &AuthSessionToken {
                typ: SessionTokenType::Session,
                ver: env.session_token_secret_version,
                jti: Uuid::new_v4().to_string(),
                exp: common::extend_current_timestamp()
                    .minutes(Action::VerifyAttr.get_jwt_token_validity_in_minutes())
                    .call()
                    .context(Location::caller())?,
                sub: user_id,
                src: Action::Login,
                aud: Action::VerifyAttr,
                dest: Action::InitMfa,
            },
            &EncodingKey::from_secret(env.session_token_secret.as_ref()),
        )
        .context(Location::caller())?;

        HandlerResponse {
            session_token,
            verification_code,
        }

    // Case 1: User hasn't called init-mfa API
    // Case 2: User has already called init-mfa API, but might haven't setup their MFA device
    } else if user_mfa.is_none() || !user_detail.verified_attrs.contains(&UserAttr::Mfa) {
        // Generate a new session token that is authorized to call init-mfa API.
        let session_token = jsonwebtoken::encode(
            &Header::new(Algorithm::HS512),
            &AuthSessionToken {
                typ: SessionTokenType::Session,
                ver: env.session_token_secret_version,
                jti: Uuid::new_v4().to_string(),
                exp: common::extend_current_timestamp()
                    .minutes(Action::InitMfa.get_jwt_token_validity_in_minutes())
                    .call()
                    .context(Location::caller())?,
                sub: user_id,
                src: Action::Login,
                aud: Action::InitMfa,
                dest: Action::InitMfa,
            },
            &EncodingKey::from_secret(env.session_token_secret.as_ref()),
        )
        .context(Location::caller())?;

        HandlerResponse {
            session_token,
            ..Default::default()
        }

    // User has already setup their MFA device
    } else {
        // Generate a new session token that is authorized to call verify-mfa API
        let session_token = jsonwebtoken::encode(
            &Header::new(Algorithm::HS512),
            &AuthSessionToken {
                typ: SessionTokenType::Session,
                ver: env.session_token_secret_version,
                jti: Uuid::new_v4().to_string(),
                exp: common::extend_current_timestamp()
                    .minutes(Action::VerifyMfa.get_jwt_token_validity_in_minutes())
                    .call()
                    .context(Location::caller())?,
                sub: user_id,
                src: Action::Login,
                aud: Action::VerifyMfa,
                dest: Action::VerifyMfa,
            },
            &EncodingKey::from_secret(env.session_token_secret.as_ref()),
        )
        .context(Location::caller())?;

        HandlerResponse {
            session_token,
            ..Default::default()
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
