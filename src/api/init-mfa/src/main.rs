use anyhow::{Context as _, Result};
use auth_lib::{
    auth_constants, auth_enums::Action, auth_user_context::AuthUserContext, AuthAttemptDb,
    AuthUserDb,
};
use aws_config::BehaviorVersion;
use aws_lambda_events::apigw::{ApiGatewayProxyRequest, ApiGatewayProxyResponse};
use common::{
    common_tracing::{self, Logger},
    ApiResponse,
};
use lambda_runtime::{run, service_fn, tracing::error, Context, Error, LambdaEvent};
use serde::Serialize;
use serde_json::Value;
use std::panic::Location;
use totp_rs::Secret;

#[derive(Debug)]
struct Env {
    dynamodb: aws_sdk_dynamodb::Client,
    ssm: aws_sdk_ssm::Client,
}

#[derive(Debug, Default, PartialEq, Serialize)]
struct HandlerResponse {
    mfa_provisioning_uri: String,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    common_tracing::init();

    let config = aws_config::load_defaults(BehaviorVersion::latest()).await;
    let dynamodb = aws_sdk_dynamodb::Client::new(&config);
    let ssm = aws_sdk_ssm::Client::new(&config);
    let env = Env { dynamodb, ssm };

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

    // Revoke this session token
    attempt_db
        .incr(Action::InitMfa)
        .jti(&*user_ctx.jti)
        .attempt(auth_constants::MAX_ACTION_ATTEMPT_MAP[&Action::InitMfa])
        .send()
        .await
        .context(Location::caller())?;

    // Generate an MFA secret for this user
    let mfa_secret = Secret::default().to_encoded().to_string();

    // Encrypt and save the MFA secret into this user record
    AuthUserDb {
        dynamodb: &env.dynamodb,
        ssm: Some(&env.ssm),
    }
    .set_mfa_secret(&mfa_secret, &user_ctx.name)
    .await
    .context(Location::caller())?;

    // Generate an MFA provisioning URI for the user to register the MFA into their device
    let mfa_provisioning_uri = format!(
        "otpauth://totp/Darkord:{email_addr}?secret={mfa_secret}&issuer=Darkord",
        email_addr = user_ctx.sub
    );

    let resp = HandlerResponse {
        mfa_provisioning_uri,
    };

    let api_resp = ApiResponse {
        code: 2000,
        payload: serde_json::to_value(resp).context(Location::caller())?,
        request_id: &context.request_id,
        ..Default::default()
    };

    Ok(api_resp.into())
}
