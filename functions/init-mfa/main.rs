#![deny(elided_lifetimes_in_paths)]

use anyhow::{Context as _, Result};
use auth_lib::{
    auth_constants,
    auth_enums::Action,
    auth_jwt::{AuthSessionToken, SessionTokenType},
    AuthAttemptDb, AuthUserContext, AuthUserDb,
};
use aws_config::BehaviorVersion;
use aws_lambda_events::apigw::{ApiGatewayProxyRequest, ApiGatewayProxyResponse};
use aws_sdk_ssm::types::Parameter;
use common::{
    common_tracing::{self, Logger},
    ApiResponse,
};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use lambda_runtime::{run, service_fn, tracing::error, Context, Error, LambdaEvent};
use magic_crypt::{new_magic_crypt, MagicCrypt256};
use serde::Serialize;
use serde_json::{json, Value};
use std::{mem, panic::Location};
use totp_rs::Secret;
use uuid::Uuid;

#[derive(Debug)]
struct Env {
    dynamodb: aws_sdk_dynamodb::Client,
    ssm: aws_sdk_ssm::Client,
    mfa_secret_key: MagicCrypt256,
    mfa_secret_version: u32,
    session_token_secret: String,
    session_token_secret_version: u32,
}

#[derive(Debug, Default, PartialEq, Serialize)]
struct HandlerResponse {
    session_token: String,
    mfa_provisioning_uri: String,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    common_tracing::init();

    let config = aws_config::load_defaults(BehaviorVersion::latest()).await;
    let dynamodb = aws_sdk_dynamodb::Client::new(&config);
    let ssm = aws_sdk_ssm::Client::new(&config);

    // Fetch the latest version of MFA secret key
    let mfa_secret_param = mem::replace(
        ssm.get_parameters_by_path()
            .path(auth_constants::MFA_PARAM_PATH)
            .with_decryption(true)
            .send()
            .await?
            .parameters
            .unwrap()
            .last_mut()
            .unwrap(),
        Parameter::builder().build(),
    );

    // Fetch the latest version of session token secret key
    let session_token_secret_param = mem::replace(
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

    let mfa_secret_key = new_magic_crypt!(mfa_secret_param.value.unwrap(), 256);

    let mfa_secret_version = mfa_secret_param
        .name
        .unwrap()
        .strip_prefix(&format!("{}/v", auth_constants::MFA_PARAM_PATH))
        .unwrap()
        .parse()?;

    let session_token_secret = session_token_secret_param.value.unwrap();

    let session_token_secret_version = session_token_secret_param
        .name
        .unwrap()
        .strip_prefix(&format!("{}/v", auth_constants::SESSION_TOKEN_PARAM_PATH))
        .unwrap()
        .parse()?;

    let env = Env {
        dynamodb,
        ssm,
        mfa_secret_key,
        mfa_secret_version,
        session_token_secret,
        session_token_secret_version,
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

    let user_ctx: AuthUserContext =
        serde_json::from_value(Value::from_iter(event.request_context.authorizer.fields))
            .context(Location::caller())?;

    let attempt_db = AuthAttemptDb {
        dynamodb: &env.dynamodb,
    };

    if attempt_db
        .is_blocked(Action::InitMfa)
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

    let user_db = AuthUserDb::new(&env.dynamodb)
        .ssm(&env.ssm)
        .mfa_secret_key(&env.mfa_secret_key)
        .mfa_secret_version(env.mfa_secret_version)
        .call();

    // Revoke this session token
    let revoke_task = attempt_db
        .incr(Action::InitMfa)
        .jti(&*user_ctx.jti)
        .attempt(Action::InitMfa.get_max_attempt())
        .send();

    let get_user_detail_task = user_db.get_detail(user_id);

    // Generate an MFA secret for this user
    let mfa_secret = Secret::default().to_encoded().to_string();

    // Encrypt and save the MFA secret into this user record
    let save_task = user_db.set_mfa_secret(user_id, &mfa_secret).send();

    // Kickstart the DB related tasks
    let (revoke_task_resp, get_user_detail_task_resp, save_task_resp) =
        tokio::join!(revoke_task, get_user_detail_task, save_task);
    revoke_task_resp.context(Location::caller())?;
    let user_detail = get_user_detail_task_resp.context(Location::caller())?;
    save_task_resp.context(Location::caller())?;

    // Generate an MFA provisioning URI for the user to register the MFA into their device
    let mfa_provisioning_uri = format!(
        "otpauth://totp/Darkord:{email_addr}?secret={mfa_secret}&issuer=Darkord",
        email_addr = user_detail.unwrap().email_addr
    );

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
            src: Action::InitMfa,
            aud: Action::VerifyMfa,
            dest: Action::VerifyMfa,
        },
        &EncodingKey::from_secret(env.session_token_secret.as_ref()),
    )
    .context(Location::caller())?;

    let resp = HandlerResponse {
        session_token,
        mfa_provisioning_uri,
    };

    let api_resp = ApiResponse {
        code: 2000,
        payload: json!(resp),
        request_id: &context.request_id,
        ..Default::default()
    };

    Ok(api_resp.into())
}
