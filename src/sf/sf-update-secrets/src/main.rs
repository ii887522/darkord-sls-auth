use advanced_random_string::{charset, random_string};
use anyhow::{Context as _, Result};
use auth_lib::{auth_constants, AuthUserDb};
use aws_config::BehaviorVersion;
use common::{
    self,
    common_tracing::{self, Logger},
};
use lambda_runtime::{run, service_fn, tracing::error, Context, Error, LambdaEvent};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, panic::Location};

#[derive(Debug)]
struct Env {
    api_gateway: aws_sdk_apigateway::Client,
    cloudfront: aws_sdk_cloudfront::Client,
    dynamodb: aws_sdk_dynamodb::Client,
    ssm: aws_sdk_ssm::Client,
}

#[derive(Debug, PartialEq, Deserialize, Serialize)]
struct HandlerRequest {}

#[derive(Debug, Default, PartialEq, Serialize)]
struct HandlerResponse {}

#[tokio::main]
async fn main() -> Result<(), Error> {
    common_tracing::init();

    let config = aws_config::load_defaults(BehaviorVersion::latest()).await;
    let api_gateway = aws_sdk_apigateway::Client::new(&config);
    let cloudfront = aws_sdk_cloudfront::Client::new(&config);
    let dynamodb = aws_sdk_dynamodb::Client::new(&config);
    let ssm = aws_sdk_ssm::Client::new(&config);

    let env = Env {
        api_gateway,
        cloudfront,
        dynamodb,
        ssm,
    };

    run(service_fn(|event: LambdaEvent<HandlerRequest>| async {
        let (event, context) = event.into_parts();

        match handler(event, &context, &env).await {
            Ok(resp) => Ok::<HandlerResponse, Error>(resp),
            Err(err) => {
                error!("{err:?}");
                Err(err.into())
            }
        }
    }))
    .await
}

async fn handler(event: HandlerRequest, context: &Context, env: &Env) -> Result<HandlerResponse> {
    serde_json::to_value(event)
        .context(Location::caller())?
        .log()
        .context(Location::caller())?;

    // Generate new API Gateway API keys
    let create_rest_api_key_task = env
        .api_gateway
        .create_api_key()
        .name(&*auth_constants::REST_API_KEY_NAME)
        .enabled(true)
        .send();

    let create_ws_api_key_task = env
        .api_gateway
        .create_api_key()
        .name(&*auth_constants::WS_API_KEY_NAME)
        .enabled(true)
        .send();

    // Fetch the latest CloudFront distribution config to be reused for update a few config
    let get_cf_dist_cfg_task = env
        .cloudfront
        .get_distribution_config()
        .id(&*auth_constants::CF_DISTRIBUTION_ID)
        .send();

    // Generate new JWT token and MFA secret SSM parameters
    let access_token_ssm_param_value =
        random_string::generate_os_secure(64, charset::URLSAFE_BASE64);

    let refresh_token_ssm_param_value =
        random_string::generate_os_secure(64, charset::URLSAFE_BASE64);

    let session_token_ssm_param_value =
        random_string::generate_os_secure(64, charset::URLSAFE_BASE64);

    let mfa_ssm_param_value = random_string::generate_os_secure(64, charset::URLSAFE_BASE64);

    let put_access_token_ssm_param_task = env
        .ssm
        .put_parameter()
        .name(auth_constants::ACCESS_TOKEN_PARAM_PATH)
        .value(access_token_ssm_param_value)
        .overwrite(true)
        .send();

    let put_refresh_token_ssm_param_task = env
        .ssm
        .put_parameter()
        .name(auth_constants::REFRESH_TOKEN_PARAM_PATH)
        .value(refresh_token_ssm_param_value)
        .overwrite(true)
        .send();

    let put_session_token_ssm_param_task = env
        .ssm
        .put_parameter()
        .name(auth_constants::SESSION_TOKEN_PARAM_PATH)
        .value(session_token_ssm_param_value)
        .overwrite(true)
        .send();

    let put_mfa_ssm_param_task = env
        .ssm
        .put_parameter()
        .name(auth_constants::MFA_PARAM_PATH)
        .value(mfa_ssm_param_value)
        .overwrite(true)
        .send();

    // Kickstart AWS service related tasks
    let (
        create_rest_api_key_task_resp,
        create_ws_api_key_task_resp,
        get_cf_dist_cfg_task_resp,
        put_access_token_ssm_param_task_resp,
        put_refresh_token_ssm_param_task_resp,
        put_session_token_ssm_param_task_resp,
        put_mfa_ssm_param_task_resp,
    ) = tokio::join!(
        create_rest_api_key_task,
        create_ws_api_key_task,
        get_cf_dist_cfg_task,
        put_access_token_ssm_param_task,
        put_refresh_token_ssm_param_task,
        put_session_token_ssm_param_task,
        put_mfa_ssm_param_task,
    );
    let create_rest_api_key_task_resp = create_rest_api_key_task_resp.context(Location::caller())?;
    let create_ws_api_key_task_resp = create_ws_api_key_task_resp.context(Location::caller())?;
    let mut get_cf_dist_cfg_task_resp = get_cf_dist_cfg_task_resp.context(Location::caller())?;
    put_access_token_ssm_param_task_resp.context(Location::caller())?;
    put_refresh_token_ssm_param_task_resp.context(Location::caller())?;
    put_session_token_ssm_param_task_resp.context(Location::caller())?;
    put_mfa_ssm_param_task_resp.context(Location::caller())?;

    // Update CloudFront distribution origin x-api-key to use the new one
    let mut origin_map = get_cf_dist_cfg_task_resp
        .distribution_config
        .as_mut()
        .unwrap()
        .origins
        .as_mut()
        .unwrap()
        .items
        .iter_mut()
        .map(|origin| (origin.domain_name.to_string(), origin))
        .collect::<HashMap<_, _>>();

    origin_map
        .get_mut(&*auth_constants::CF_ORIGIN_WS_API_DOMAIN_NAME)
        .unwrap()
        .custom_headers
        .as_mut()
        .unwrap()
        .items
        .as_mut()
        .unwrap()
        .iter_mut()
        .find(|header| header.header_name == "x-api-key")
        .unwrap()
        .header_value = create_ws_api_key_task_resp.value.unwrap_or_default();

    origin_map
        .get_mut(&*auth_constants::CF_ORIGIN_REST_API_DOMAIN_NAME)
        .unwrap()
        .custom_headers
        .as_mut()
        .unwrap()
        .items
        .as_mut()
        .unwrap()
        .iter_mut()
        .find(|header| header.header_name == "x-api-key")
        .unwrap()
        .header_value = create_rest_api_key_task_resp.value.unwrap_or_default();

    let update_cf_dist_cfg_task = env
        .cloudfront
        .update_distribution()
        .distribution_config(get_cf_dist_cfg_task_resp.distribution_config.unwrap())
        .id(&*auth_constants::CF_DISTRIBUTION_ID)
        .if_match(get_cf_dist_cfg_task_resp.e_tag.unwrap_or_default())
        .send();

    let user_db = AuthUserDb {
        dynamodb: &env.dynamodb,
        ssm: Some(&env.ssm),
    };

    let get_next_user_id_task = user_db.get_next_user_id();

    // Kickstart AWS service related tasks
    let (update_cf_dist_cfg_task_resp, get_next_user_id_task_resp) =
        tokio::join!(update_cf_dist_cfg_task, get_next_user_id_task);
    update_cf_dist_cfg_task_resp.context(Location::caller())?;
    let next_user_id = get_next_user_id_task_resp.context(Location::caller())?;

    for user_id in 1..next_user_id {
        user_db
            .rotate_mfa_secret(user_id)
            .await
            .context(Location::caller())?;

        if common::is_almost_timeout(context)
            .call()
            .context(Location::caller())?
        {
            // todo: Handle state transition due to lambda timeout limit
        }
    }

    Ok(HandlerResponse {})
}
