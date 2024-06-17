use anyhow::{Context as _, Result};
use auth_lib::{
    auth_constants,
    auth_enums::Action,
    auth_jwt::{AuthSessionToken, SessionTokenType},
    AuthUserDb,
};
use aws_config::BehaviorVersion;
use aws_lambda_events::apigw::{ApiGatewayProxyRequest, ApiGatewayProxyResponse};
use common::{
    self,
    common_serde::Request,
    common_tracing::{self, Logger},
    ApiResponse, TrimmedString,
};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use lambda_runtime::{run, service_fn, tracing::error, Context, Error, LambdaEvent};
use serde::{Deserialize, Serialize};
use std::panic::Location;
use uuid::Uuid;
use validator::Validate;

#[derive(Debug)]
struct Env {
    dynamodb: aws_sdk_dynamodb::Client,
    session_token_secret: String,
}

#[derive(Debug, PartialEq, Deserialize, Validate)]
struct HandlerRequest {
    #[validate(email, length(min = 1))]
    email_addr: TrimmedString,
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

    let user_db = AuthUserDb {
        dynamodb: &env.dynamodb,
        ssm: None,
    };

    let user_id = user_db
        .get_user_id(&req.email_addr)
        .await
        .context(Location::caller())?;

    // Generate a new verification code and update it into the user record
    let verification_code = common::gen_secret_digits().call();

    if let Some(user_id) = user_id {
        user_db
            .set_verification_code(user_id, verification_code.to_string())
            .await
            .context(Location::caller())?;

        // todo: Send a verification email to the given email address with the verification code
        // todo: Email content based on the given locale
    }

    // Generate a new session token that is authorized to call verify-email API
    let session_token = jsonwebtoken::encode(
        &Header::new(Algorithm::HS512),
        &AuthSessionToken {
            typ: SessionTokenType::Session,
            jti: Uuid::new_v4().to_string(),
            sub: user_id.unwrap_or_else(|| {
                // Generate a fake user_id based on the email address given
                common::hash(&req.email_addr) as u32
            }),
            exp: common::extend_current_timestamp()
                .minutes(Action::VerifyAttr.get_jwt_token_validity_in_minutes())
                .call()
                .context(Location::caller())?,
            aud: Action::VerifyAttr,
            dest: Action::ResetPassword,
        },
        &EncodingKey::from_secret(env.session_token_secret.as_ref()),
    )
    .context(Location::caller())?;

    let resp = HandlerResponse {
        session_token,
        verification_code,
    };

    let api_resp = ApiResponse {
        code: 2000,
        payload: serde_json::to_value(resp).context(Location::caller())?,
        request_id: &context.request_id,
        ..Default::default()
    };

    Ok(api_resp.into())
}
