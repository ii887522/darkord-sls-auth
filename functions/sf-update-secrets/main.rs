#![deny(elided_lifetimes_in_paths)]

use advanced_random_string::{charset, random_string};
use anyhow::{Context as _, Result};
use auth_lib::{auth_constants, auth_sf_models::UpdateSecretsResponse, AuthUserDb};
use aws_config::BehaviorVersion;
use aws_sdk_ssm::types::{Parameter, ParameterType};
use common::{
    self,
    common_tracing::{self, Logger},
};
use lambda_runtime::{run, service_fn, tracing::error, Context, Error, LambdaEvent};
use magic_crypt::new_magic_crypt;
use serde_json::{json, Value};
use std::{collections::HashMap, mem, panic::Location, time::Duration};

#[derive(Debug)]
struct Env {
    api_gateway: aws_sdk_apigateway::Client,
    cloudfront: aws_sdk_cloudfront::Client,
    dynamodb: aws_sdk_dynamodb::Client,
    ssm: aws_sdk_ssm::Client,
}

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

async fn handler(mut event: Value, context: &Context, env: &Env) -> Result<Value> {
    event.log().context(Location::caller())?;
    let event = event.as_object_mut().unwrap();

    let is_continue = event
        .remove("is_continue")
        .unwrap_or_default()
        .as_bool()
        .unwrap_or_default();

    let update_secrets_resp = if let Some(update_secrets_resp) = event
        .remove("update_secrets_resp")
        .map(serde_json::from_value::<UpdateSecretsResponse>)
    {
        Some(update_secrets_resp?)
    } else {
        None
    };

    // First iteration of this lambda invocation
    if !is_continue {
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

        // Find the latest version of each SSM parameters
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
            create_rest_api_key_task_resp,
            create_ws_api_key_task_resp,
            get_cf_dist_cfg_task_resp,
            get_access_token_ssm_params_task_resp,
            get_refresh_token_ssm_params_task_resp,
            get_session_token_ssm_params_task_resp,
            get_mfa_ssm_params_task_resp,
        ) = tokio::join!(
            create_rest_api_key_task,
            create_ws_api_key_task,
            get_cf_dist_cfg_task,
            get_access_token_ssm_params_task,
            get_refresh_token_ssm_params_task,
            get_session_token_ssm_params_task,
            get_mfa_ssm_params_task
        );
        let create_rest_api_key_task_resp =
            create_rest_api_key_task_resp.context(Location::caller())?;
        let create_ws_api_key_task_resp = create_ws_api_key_task_resp.context(Location::caller())?;
        let mut get_cf_dist_cfg_task_resp = get_cf_dist_cfg_task_resp.context(Location::caller())?;
        let get_access_token_ssm_params_task_resp =
            get_access_token_ssm_params_task_resp.context(Location::caller())?;
        let get_refresh_token_ssm_params_task_resp =
            get_refresh_token_ssm_params_task_resp.context(Location::caller())?;
        let get_session_token_ssm_params_task_resp =
            get_session_token_ssm_params_task_resp.context(Location::caller())?;
        let get_mfa_ssm_params_task_resp =
            get_mfa_ssm_params_task_resp.context(Location::caller())?;

        // Associate the generated API keys to the respective usage plans
        let create_rest_api_usage_plan_key_task = env
            .api_gateway
            .create_usage_plan_key()
            .usage_plan_id(&*auth_constants::REST_API_USAGE_PLAN_ID)
            .key_id(create_rest_api_key_task_resp.id.unwrap())
            .key_type("API_KEY")
            .send();

        let create_ws_api_usage_plan_key_task = env
            .api_gateway
            .create_usage_plan_key()
            .usage_plan_id(&*auth_constants::WS_API_USAGE_PLAN_ID)
            .key_id(create_ws_api_key_task_resp.id.unwrap())
            .key_type("API_KEY")
            .send();

        // Generate new JWT token and MFA secret SSM parameters
        let access_token_ssm_param_name = format!(
            "{name}/v{version:0>3}",
            name = auth_constants::ACCESS_TOKEN_PARAM_PATH,
            version = get_access_token_ssm_params_task_resp
                .parameters
                .unwrap()
                .last()
                .unwrap()
                .name
                .as_ref()
                .unwrap()
                .strip_prefix(&format!("{}/v", auth_constants::ACCESS_TOKEN_PARAM_PATH))
                .unwrap()
                .parse::<u32>()
                .context(Location::caller())?
                + 1
        );

        let refresh_token_ssm_param_name = format!(
            "{name}/v{version:0>3}",
            name = auth_constants::REFRESH_TOKEN_PARAM_PATH,
            version = get_refresh_token_ssm_params_task_resp
                .parameters
                .unwrap()
                .last()
                .unwrap()
                .name
                .as_ref()
                .unwrap()
                .strip_prefix(&format!("{}/v", auth_constants::REFRESH_TOKEN_PARAM_PATH))
                .unwrap()
                .parse::<u32>()
                .context(Location::caller())?
                + 1
        );

        let session_token_ssm_param_name = format!(
            "{name}/v{version:0>3}",
            name = auth_constants::SESSION_TOKEN_PARAM_PATH,
            version = get_session_token_ssm_params_task_resp
                .parameters
                .unwrap()
                .last()
                .unwrap()
                .name
                .as_ref()
                .unwrap()
                .strip_prefix(&format!("{}/v", auth_constants::SESSION_TOKEN_PARAM_PATH))
                .unwrap()
                .parse::<u32>()
                .context(Location::caller())?
                + 1
        );

        let mfa_ssm_param_name = format!(
            "{name}/v{version:0>3}",
            name = auth_constants::MFA_PARAM_PATH,
            version = get_mfa_ssm_params_task_resp
                .parameters
                .unwrap()
                .last()
                .unwrap()
                .name
                .as_ref()
                .unwrap()
                .strip_prefix(&format!("{}/v", auth_constants::MFA_PARAM_PATH))
                .unwrap()
                .parse::<u32>()
                .context(Location::caller())?
                + 1
        );

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
            .name(access_token_ssm_param_name)
            .value(access_token_ssm_param_value)
            .r#type(ParameterType::SecureString)
            .send();

        let put_refresh_token_ssm_param_task = env
            .ssm
            .put_parameter()
            .name(refresh_token_ssm_param_name)
            .value(refresh_token_ssm_param_value)
            .r#type(ParameterType::SecureString)
            .send();

        let put_session_token_ssm_param_task = env
            .ssm
            .put_parameter()
            .name(session_token_ssm_param_name)
            .value(session_token_ssm_param_value)
            .r#type(ParameterType::SecureString)
            .send();

        let put_mfa_ssm_param_task = env
            .ssm
            .put_parameter()
            .name(mfa_ssm_param_name)
            .value(mfa_ssm_param_value)
            .r#type(ParameterType::SecureString)
            .send();

        // Kickstart AWS service related tasks
        let (
            create_rest_api_usage_plan_key_task_resp,
            create_ws_api_usage_plan_key_task_resp,
            put_access_token_ssm_param_task_resp,
            put_refresh_token_ssm_param_task_resp,
            put_session_token_ssm_param_task_resp,
            put_mfa_ssm_param_task_resp,
        ) = tokio::join!(
            create_rest_api_usage_plan_key_task,
            create_ws_api_usage_plan_key_task,
            put_access_token_ssm_param_task,
            put_refresh_token_ssm_param_task,
            put_session_token_ssm_param_task,
            put_mfa_ssm_param_task,
        );
        create_rest_api_usage_plan_key_task_resp.context(Location::caller())?;
        create_ws_api_usage_plan_key_task_resp.context(Location::caller())?;
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

        env.cloudfront
            .update_distribution()
            .distribution_config(get_cf_dist_cfg_task_resp.distribution_config.unwrap())
            .id(&*auth_constants::CF_DISTRIBUTION_ID)
            .if_match(get_cf_dist_cfg_task_resp.e_tag.unwrap_or_default())
            .send()
            .await
            .context(Location::caller())?;

        // Delay 5 seconds so that the MFA SSM parameter we just put is eventually consistent and we can get it
        tokio::time::sleep(Duration::from_secs(5)).await;
    }

    // Fetch the latest version of MFA secret key
    let mfa_secret_param = mem::replace(
        env.ssm
            .get_parameters_by_path()
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

    let mfa_secret_key = new_magic_crypt!(mfa_secret_param.value.unwrap(), 256);

    let mfa_secret_version = mfa_secret_param
        .name
        .unwrap()
        .strip_prefix(&format!("{}/v", auth_constants::MFA_PARAM_PATH))
        .unwrap()
        .parse::<u32>()?;

    let mut user_db = AuthUserDb::new(&env.dynamodb)
        .ssm(&env.ssm)
        .mfa_secret_key(&mfa_secret_key)
        .mfa_secret_version(mfa_secret_version)
        .call();

    let (start_user_id, end_user_id) = if let Some(update_secrets_resp) = update_secrets_resp {
        (
            update_secrets_resp.start_user_id,
            update_secrets_resp.end_user_id,
        )
    } else {
        let next_user_id = user_db
            .get_next_user_id()
            .await
            .context(Location::caller())?;

        (1, next_user_id)
    };

    for user_id in start_user_id..end_user_id {
        user_db
            .rotate_mfa_secret(user_id)
            .await
            .context(Location::caller())?;

        if common::is_almost_timeout(context)
            .call()
            .context(Location::caller())?
        {
            let resp = UpdateSecretsResponse {
                start_user_id: user_id + 1,
                end_user_id,
            };

            event.insert("is_continue".to_string(), json!(true));
            event.insert("update_secrets_resp".to_string(), json!(resp));
            break;
        }
    }

    Ok(json!(event))
}
