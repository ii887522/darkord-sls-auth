#![deny(elided_lifetimes_in_paths)]

use anyhow::{Context as _, Result};
use auth_lib::auth_constants;
use aws_config::BehaviorVersion;
use common::{
    self,
    common_tracing::{self, Logger},
};
use futures::future;
use lambda_runtime::{run, service_fn, tracing::error, Context, Error, LambdaEvent};
use serde_json::Value;
use std::panic::Location;

#[derive(Debug)]
struct Env {
    api_gateway: aws_sdk_apigateway::Client,
    ssm: aws_sdk_ssm::Client,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    common_tracing::init();

    let config = aws_config::load_defaults(BehaviorVersion::latest()).await;
    let api_gateway = aws_sdk_apigateway::Client::new(&config);
    let ssm = aws_sdk_ssm::Client::new(&config);
    let env = Env { api_gateway, ssm };

    run(service_fn(|event: LambdaEvent<Value>| async {
        let (event, context) = event.into_parts();

        match handler(event, &context, &env).await {
            Ok(resp) => Ok::<Value, Error>(resp),
            Err(err) => {
                error!("{err:?}");
                Err(err.into())
            }
        }
    }))
    .await
}

async fn handler(mut event: Value, _context: &Context, env: &Env) -> Result<Value> {
    event.log().context(Location::caller())?;

    // Fetch a list of API Gateway API keys
    let get_rest_api_keys_task = auth_constants::REST_API_KEY_NAME.with(|rest_api_key_name| {
        env.api_gateway
            .get_api_keys()
            .name_query(rest_api_key_name)
            .send()
    });

    let get_ws_api_keys_task = auth_constants::WS_API_KEY_NAME.with(|ws_api_key_name| {
        env.api_gateway
            .get_api_keys()
            .name_query(ws_api_key_name)
            .send()
    });

    // Fetch a list of JWT token and MFA secret SSM parameters
    let get_access_token_ssm_params_task = env
        .ssm
        .get_parameters_by_path()
        .path(auth_constants::ACCESS_TOKEN_PARAM_PATH)
        .send();

    let get_refresh_token_ssm_params_task = env
        .ssm
        .get_parameters_by_path()
        .path(auth_constants::REFRESH_TOKEN_PARAM_PATH)
        .send();

    let get_session_token_ssm_params_task = env
        .ssm
        .get_parameters_by_path()
        .path(auth_constants::SESSION_TOKEN_PARAM_PATH)
        .send();

    let get_mfa_ssm_params_task = env
        .ssm
        .get_parameters_by_path()
        .path(auth_constants::MFA_PARAM_PATH)
        .send();

    // Kickstart AWS service related tasks
    let (
        get_rest_api_keys_task_resp,
        get_ws_api_keys_task_resp,
        get_access_token_ssm_params_task_resp,
        get_refresh_token_ssm_params_task_resp,
        get_session_token_ssm_params_task_resp,
        get_mfa_ssm_params_task_resp,
    ) = tokio::join!(
        get_rest_api_keys_task,
        get_ws_api_keys_task,
        get_access_token_ssm_params_task,
        get_refresh_token_ssm_params_task,
        get_session_token_ssm_params_task,
        get_mfa_ssm_params_task,
    );
    let get_rest_api_keys_task_resp = get_rest_api_keys_task_resp.context(Location::caller())?;
    let get_ws_api_keys_task_resp = get_ws_api_keys_task_resp.context(Location::caller())?;
    let get_access_token_ssm_params_task_resp =
        get_access_token_ssm_params_task_resp.context(Location::caller())?;
    let get_refresh_token_ssm_params_task_resp =
        get_refresh_token_ssm_params_task_resp.context(Location::caller())?;
    let get_session_token_ssm_params_task_resp =
        get_session_token_ssm_params_task_resp.context(Location::caller())?;
    let get_mfa_ssm_params_task_resp = get_mfa_ssm_params_task_resp.context(Location::caller())?;

    let mut rest_api_keys = get_rest_api_keys_task_resp.items.unwrap();
    let mut ws_api_keys = get_ws_api_keys_task_resp.items.unwrap();
    rest_api_keys.sort_unstable_by_key(|api_key| api_key.created_date);
    ws_api_keys.sort_unstable_by_key(|api_key| api_key.created_date);

    // Cleanup old API keys
    let delete_api_keys_task = future::join_all(
        rest_api_keys
            .into_iter()
            .rev()
            .skip(1)
            .rev()
            .chain(ws_api_keys.into_iter().rev().skip(1).rev())
            .map(|api_key| {
                env.api_gateway
                    .delete_api_key()
                    .api_key(api_key.id.unwrap())
                    .send()
            }),
    );

    // Cleanup old JWT token and MFA secret SSM parameters
    let del_ssm_params_task = future::join_all(
        get_access_token_ssm_params_task_resp
        .parameters
        .unwrap()
        .into_iter()
        .rev()
        .skip(1)
        .rev()
        .chain(
            get_refresh_token_ssm_params_task_resp
                .parameters
                .unwrap()
                .into_iter()
                .rev()
                .skip(1)
                .rev(),
        )
        .chain(
            get_session_token_ssm_params_task_resp
                .parameters
                .unwrap()
                .into_iter()
                .rev()
                .skip(1)
                .rev(),
        )
        .chain(
            get_mfa_ssm_params_task_resp
                .parameters
                .unwrap()
                .into_iter()
                .rev()
                .skip(1)
                .rev(),
        )
        .map(|ssm_param| ssm_param.name.unwrap())
        .collect::<Vec<_>>()
        .chunks(10) // SSM delete_parameters() names parameter only support at most 10 names
        .map(|ssm_param_names| env.ssm.delete_parameters().set_names(Some(ssm_param_names.to_vec())).send()),
    );

    // Kickstart AWS service related tasks
    let (delete_api_keys_task_resp, del_ssm_params_task_resp) =
        tokio::join!(delete_api_keys_task, del_ssm_params_task);
    for delete_api_key_task_resp in delete_api_keys_task_resp {
        delete_api_key_task_resp.context(Location::caller())?;
    }
    for del_ssm_params_task_resp in del_ssm_params_task_resp {
        del_ssm_params_task_resp.context(Location::caller())?;
    }

    Ok(event)
}
