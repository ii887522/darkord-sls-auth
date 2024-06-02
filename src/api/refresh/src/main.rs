use anyhow::{Context as _, Result};
use auth_lib::{
    auth_constants,
    auth_enums::Role,
    auth_jwt::{AccessTokenType, AuthAccessToken},
    AuthUserContext, AuthValidTokenPairDb,
};
use aws_config::BehaviorVersion;
use aws_lambda_events::apigw::{ApiGatewayProxyRequest, ApiGatewayProxyResponse};
use common::{
    common_tracing::{self, Logger},
    ApiResponse, CommonError,
};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use lambda_runtime::{run, service_fn, tracing::error, Context, Error, LambdaEvent};
use serde::Serialize;
use serde_json::Value;
use std::panic::Location;
use uuid::Uuid;

#[derive(Debug)]
struct Env {
    dynamodb: aws_sdk_dynamodb::Client,
    access_token_secret: String,
}

#[derive(Debug, Default, PartialEq, Serialize)]
struct HandlerResponse {
    access_token: String,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Error> {
    common_tracing::init();

    let config = aws_config::load_defaults(BehaviorVersion::latest()).await;
    let dynamodb = aws_sdk_dynamodb::Client::new(&config);
    let ssm = aws_sdk_ssm::Client::new(&config);

    let access_token_secret = ssm
        .get_parameter()
        .name(auth_constants::ACCESS_TOKEN_PARAM_PATH)
        .with_decryption(true)
        .send()
        .await?
        .parameter
        .unwrap()
        .value
        .unwrap();

    let env = Env {
        dynamodb,
        access_token_secret,
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

    let user_ctx: AuthUserContext =
        serde_json::from_value(Value::from_iter(event.request_context.authorizer.fields))
            .context(Location::caller())?;

    let access_token_jti = Uuid::new_v4().to_string();

    let db_resp = AuthValidTokenPairDb {
        dynamodb: &env.dynamodb,
    }
    .update_item(&user_ctx.jti, &access_token_jti)
    .await
    .context(Location::caller());

    if let Err(err) = db_resp {
        let api_resp = err
            .downcast::<CommonError>()
            .context(Location::caller())?
            .into_api_resp(&context.request_id);

        return Ok(api_resp.into());
    }

    let access_token = jsonwebtoken::encode(
        &Header::new(Algorithm::HS512),
        &AuthAccessToken {
            typ: AccessTokenType::Access,
            jti: access_token_jti,
            exp: common::extend_current_timestamp()
                .minutes(5u64)
                .call()
                .context(Location::caller())?,
            sub: user_ctx.sub,
            name: user_ctx.name,
            roles: vec![Role::User],
            orig: user_ctx.jti,
        },
        &EncodingKey::from_secret(env.access_token_secret.as_ref()),
    )
    .context(Location::caller())?;

    let api_resp = ApiResponse {
        code: 2000,
        payload: serde_json::to_value(HandlerResponse { access_token })
            .context(Location::caller())?,
        request_id: &context.request_id,
        ..Default::default()
    };

    Ok(api_resp.into())
}
