#![deny(elided_lifetimes_in_paths)]

use anyhow::{Context as _, Result};
use auth_lib::{AuthUserContext, AuthValidTokenPairDb};
use aws_config::BehaviorVersion;
use aws_lambda_events::apigw::{ApiGatewayProxyRequest, ApiGatewayProxyResponse};
use common::{
    self,
    common_tracing::{self, Logger},
    ApiResponse, CommonError,
};
use lambda_runtime::{run, service_fn, tracing::error, Context, Error, LambdaEvent};
use serde::Serialize;
use serde_json::{json, Value};
use std::panic::Location;

#[derive(Debug)]
struct Env {
    dynamodb: aws_sdk_dynamodb::Client,
}

#[derive(Debug, Default, PartialEq, Serialize)]
struct HandlerResponse {}

#[tokio::main]
async fn main() -> Result<(), Error> {
    common_tracing::init();

    let config = aws_config::load_defaults(BehaviorVersion::latest()).await;
    let dynamodb = aws_sdk_dynamodb::Client::new(&config);
    let env = Env { dynamodb };

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

    let db_resp = AuthValidTokenPairDb {
        dynamodb: &env.dynamodb,
    }
    .delete_valid_token_pair(&user_ctx.orig)
    .await
    .context(Location::caller());

    if let Err(err) = db_resp {
        let api_resp = err
            .downcast::<CommonError>()
            .context(Location::caller())?
            .into_api_resp(&context.request_id);

        return Ok(api_resp.into());
    }

    let api_resp = ApiResponse {
        code: 2000,
        payload: json!(HandlerResponse {}),
        request_id: &context.request_id,
        ..Default::default()
    };

    Ok(api_resp.into())
}
