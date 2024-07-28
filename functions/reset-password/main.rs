#![deny(elided_lifetimes_in_paths)]

use anyhow::{Context as _, Result};
use auth_lib::{auth_enums::Action, AuthAttemptDb, AuthUserContext, AuthUserDb};
use aws_config::BehaviorVersion;
use aws_lambda_events::apigw::{ApiGatewayProxyRequest, ApiGatewayProxyResponse};
use common::{
    self,
    common_serde::Request,
    common_tracing::{self, Logger},
    ApiResponse,
};
use lambda_runtime::{run, service_fn, tracing::error, Context, Error, LambdaEvent};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::panic::Location;
use validator::Validate;

#[derive(Debug)]
struct Env {
    dynamodb: aws_sdk_dynamodb::Client,
}

#[derive(Debug, PartialEq, Deserialize, Validate)]
struct HandlerRequest {
    #[validate(length(min = 1))]
    password: String,
}

impl Request for HandlerRequest {}

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
        .is_blocked(Action::ResetPassword)
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

    // Revoke the session token in DynamoDB
    let revoke_task = attempt_db
        .incr(Action::ResetPassword)
        .jti(&*user_ctx.jti)
        .attempt(Action::ResetPassword.get_max_attempt())
        .send();

    let user_id = user_ctx.sub.parse().context(Location::caller())?;

    let user_db = AuthUserDb::new(&env.dynamodb).call();
    let update_task = user_db.set_password(user_id, &req.password);

    // Kickstart the DB related tasks
    let (revoke_task_resp, update_task_resp) = tokio::join!(revoke_task, update_task);
    revoke_task_resp.context(Location::caller())?;
    update_task_resp.context(Location::caller())?;

    let api_resp = ApiResponse {
        code: 2000,
        payload: json!(HandlerResponse {}),
        request_id: &context.request_id,
        ..Default::default()
    };

    Ok(api_resp.into())
}
