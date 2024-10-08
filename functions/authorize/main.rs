#![deny(elided_lifetimes_in_paths)]

use anyhow::{bail, Context as _, Result};
use auth_lib::{
    auth_constants,
    auth_enums::{Action, JwtToken},
    auth_jwt::{AuthAccessToken, AuthRefreshToken, AuthSessionToken, JwtTokenSecrets},
    AuthError, AuthRbacDb, AuthRbacExt, AuthUserContext, AuthValidTokenPairDb,
};
use aws_config::BehaviorVersion;
use aws_lambda_events::{
    apigw::{
        ApiGatewayCustomAuthorizerPolicy, ApiGatewayCustomAuthorizerRequest,
        ApiGatewayCustomAuthorizerRequestTypeRequest, ApiGatewayCustomAuthorizerResponse,
    },
    http::HeaderValue,
    iam::{IamPolicyEffect, IamPolicyStatement},
};
use common::{
    self,
    common_tracing::{self, Logger},
    method_arn::MethodArn,
};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use lambda_runtime::{
    run, service_fn,
    tracing::{error, info},
    Context, Error, LambdaEvent,
};
use optarg2chain::optarg_fn;
use serde_json::{json, Map, Value};
use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    panic::Location,
};

#[derive(Debug)]
struct Env {
    dynamodb: aws_sdk_dynamodb::Client,
    jwt_token_secrets_map: HashMap<u64, JwtTokenSecrets>,
    rbac_cache: RefCell<HashMap<String, AuthRbacExt>>,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    common_tracing::init();

    let config = aws_config::load_defaults(BehaviorVersion::latest()).await;
    let dynamodb = aws_sdk_dynamodb::Client::new(&config);
    let ssm = aws_sdk_ssm::Client::new(&config);

    let get_access_token_secrets_task = ssm
        .get_parameters_by_path()
        .path(auth_constants::ACCESS_TOKEN_PARAM_PATH)
        .with_decryption(true)
        .send();

    let get_refresh_token_secrets_task = ssm
        .get_parameters_by_path()
        .path(auth_constants::REFRESH_TOKEN_PARAM_PATH)
        .with_decryption(true)
        .send();

    let get_session_token_secrets_task = ssm
        .get_parameters_by_path()
        .path(auth_constants::SESSION_TOKEN_PARAM_PATH)
        .with_decryption(true)
        .send();

    let (
        get_access_token_secrets_task_resp,
        get_refresh_token_secrets_task_resp,
        get_session_token_secrets_task_resp,
    ) = tokio::join!(
        get_access_token_secrets_task,
        get_refresh_token_secrets_task,
        get_session_token_secrets_task
    );

    let access_token_secrets = get_access_token_secrets_task_resp?.parameters.unwrap();
    let refresh_token_secrets = get_refresh_token_secrets_task_resp?.parameters.unwrap();
    let session_token_secrets = get_session_token_secrets_task_resp?.parameters.unwrap();

    let mut jwt_token_secrets_map = HashMap::<_, JwtTokenSecrets>::with_capacity(
        access_token_secrets.len() + refresh_token_secrets.len() + session_token_secrets.len(),
    );

    for access_token_secret in access_token_secrets {
        jwt_token_secrets_map
            .entry(
                access_token_secret
                    .name
                    .unwrap()
                    .strip_prefix(&format!("{}/v", auth_constants::ACCESS_TOKEN_PARAM_PATH))
                    .unwrap()
                    .parse()?,
            )
            .or_default()
            .access_token_secret = access_token_secret.value.unwrap();
    }

    for refresh_token_secret in refresh_token_secrets {
        jwt_token_secrets_map
            .entry(
                refresh_token_secret
                    .name
                    .unwrap()
                    .strip_prefix(&format!("{}/v", auth_constants::REFRESH_TOKEN_PARAM_PATH))
                    .unwrap()
                    .parse()?,
            )
            .or_default()
            .refresh_token_secret = refresh_token_secret.value.unwrap();
    }

    for session_token_secret in session_token_secrets {
        jwt_token_secrets_map
            .entry(
                session_token_secret
                    .name
                    .unwrap()
                    .strip_prefix(&format!("{}/v", auth_constants::SESSION_TOKEN_PARAM_PATH))
                    .unwrap()
                    .parse()?,
            )
            .or_default()
            .session_token_secret = session_token_secret.value.unwrap();
    }

    let env = Env {
        dynamodb,
        jwt_token_secrets_map,
        rbac_cache: RefCell::new(HashMap::new()),
    };

    run(service_fn(|event: LambdaEvent<Value>| async {
        let (event, context) = event.into_parts();

        match handler(event, &context, &env).await {
            Ok(resp) => Ok::<Value, Error>(resp),
            Err(err) => match err.downcast::<AuthError>() {
                Ok(err @ AuthError::Unauthorized) => {
                    info!("{err:?}");
                    Err("Unauthorized".into())
                }
                Err(err) => {
                    error!("{err:?}");
                    Ok(json!("unauthorized"))
                }
            },
        }
    }))
    .await
}

async fn handler(event: Value, _context: &Context, env: &Env) -> Result<Value> {
    let (auth_token, method_arn) =
        match event.as_object().context(Location::caller())?["type"].as_str() {
            Some("TOKEN") => {
                let mut event: ApiGatewayCustomAuthorizerRequest =
                    serde_json::from_value(event).context(Location::caller())?;

                event.log().context(Location::caller())?;

                (
                    event.authorization_token.unwrap_or_default(),
                    event.method_arn.unwrap_or_default(),
                )
            }
            Some("REQUEST") => {
                let mut event: ApiGatewayCustomAuthorizerRequestTypeRequest =
                    serde_json::from_value(event).context(Location::caller())?;

                event.log().context(Location::caller())?;

                (
                    event
                        .headers
                        .get("Authorization")
                        .unwrap_or(&HeaderValue::from_static(""))
                        .to_str()
                        .unwrap_or_default()
                        .to_string(),
                    event.method_arn.unwrap_or_default(),
                )
            }
            _ => ("".to_string(), "".to_string()),
        };

    let resp = match decode(&auth_token, env) {
        Ok(JwtToken::Access(access_token)) => {
            auth_access_token(access_token, &method_arn, env).await?
        }
        Ok(JwtToken::Refresh(refresh_token)) => {
            auth_refresh_token(refresh_token, &method_arn, env).await?
        }
        Ok(JwtToken::Session(session_token)) => {
            auth_session_token(session_token, &method_arn).await
        }
        Err(err) => {
            let err = err
                .downcast::<jsonwebtoken::errors::Error>()
                .context(Location::caller())?;

            match err.kind() {
                jsonwebtoken::errors::ErrorKind::InvalidToken
                | jsonwebtoken::errors::ErrorKind::InvalidSignature
                | jsonwebtoken::errors::ErrorKind::InvalidAlgorithmName
                | jsonwebtoken::errors::ErrorKind::InvalidKeyFormat
                | jsonwebtoken::errors::ErrorKind::MissingRequiredClaim(_)
                | jsonwebtoken::errors::ErrorKind::ExpiredSignature
                | jsonwebtoken::errors::ErrorKind::InvalidAudience
                | jsonwebtoken::errors::ErrorKind::InvalidAlgorithm
                | jsonwebtoken::errors::ErrorKind::MissingAlgorithm
                | jsonwebtoken::errors::ErrorKind::Json(_)
                | jsonwebtoken::errors::ErrorKind::Utf8(_) => {
                    info!("{err:?}");
                    bail!(AuthError::Unauthorized);
                }
                _ => bail!(err),
            }
        }
    };

    serde_json::to_value(resp).context(Location::caller())
}

fn decode(jwt_token: &str, env: &Env) -> Result<JwtToken> {
    let mut disabled_validation = Validation::new(Algorithm::HS512);
    disabled_validation.insecure_disable_signature_validation();
    disabled_validation.validate_aud = false;

    let unsafe_jwt_token = jsonwebtoken::decode::<Value>(
        jwt_token,
        &DecodingKey::from_secret(&[]),
        &disabled_validation,
    )?;

    let empty_claims = Map::new();
    let unsafe_claims = unsafe_jwt_token.claims.as_object().unwrap_or(&empty_claims);

    // Find the type of this JWT token
    let jwt_token = match unsafe_claims.get("typ") {
        Some(Value::String(typ)) => {
            let mut validation = Validation::new(Algorithm::HS512);
            validation.set_audience(auth_constants::AUDIENCE_ACTIONS);

            let jwt_token_version = unsafe_claims["ver"].as_u64().unwrap();

            // Ensure the given JWT token is valid
            match typ.as_str() {
                auth_constants::TOKEN_TYPE_ACCESS => {
                    let access_token_secret = DecodingKey::from_secret(
                        env.jwt_token_secrets_map[&jwt_token_version]
                            .access_token_secret
                            .as_bytes(),
                    );

                    let jwt_token =
                        jsonwebtoken::decode(jwt_token, &access_token_secret, &validation)?;

                    JwtToken::Access(jwt_token.claims)
                }
                auth_constants::TOKEN_TYPE_REFRESH => {
                    let refresh_token_secret = DecodingKey::from_secret(
                        env.jwt_token_secrets_map[&jwt_token_version]
                            .refresh_token_secret
                            .as_bytes(),
                    );

                    let jwt_token =
                        jsonwebtoken::decode(jwt_token, &refresh_token_secret, &validation)?;

                    JwtToken::Refresh(jwt_token.claims)
                }
                auth_constants::TOKEN_TYPE_SESSION => {
                    let session_token_secret = DecodingKey::from_secret(
                        env.jwt_token_secrets_map[&jwt_token_version]
                            .session_token_secret
                            .as_bytes(),
                    );

                    let jwt_token =
                        jsonwebtoken::decode(jwt_token, &session_token_secret, &validation)?;

                    JwtToken::Session(jwt_token.claims)
                }
                typ => panic!("Unknown JWT token type: {typ}"),
            }
        }
        _ => panic!("typ not found"),
    };

    Ok(jwt_token)
}

#[optarg_fn(GenPolicyBuilder, call)]
fn gen_policy(
    method_arn: String,
    principal_id: String,
    effect: IamPolicyEffect,
    jti: String,
    #[optarg_default] sub: String,
    #[optarg_default] src: Option<Action>,
    #[optarg_default] dest: Option<Action>,
    #[optarg_default] orig: String,
) -> ApiGatewayCustomAuthorizerResponse<AuthUserContext> {
    ApiGatewayCustomAuthorizerResponse {
        principal_id: Some(principal_id),
        policy_document: ApiGatewayCustomAuthorizerPolicy {
            version: Some("2012-10-17".to_string()),
            statement: vec![IamPolicyStatement {
                action: vec!["execute-api:Invoke".to_string()],
                effect,
                resource: vec![method_arn],
                condition: None,
            }],
        },
        context: AuthUserContext {
            jti,
            sub,
            src,
            dest,
            orig,
        },
        usage_identifier_key: None,
    }
}

async fn auth_access_token(
    AuthAccessToken {
        jti,
        sub,
        roles,
        orig,
        ..
    }: AuthAccessToken,
    method_arn_str: &str,
    env: &Env,
) -> Result<ApiGatewayCustomAuthorizerResponse<AuthUserContext>> {
    let Some(valid_token_pair) = AuthValidTokenPairDb {
        dynamodb: &env.dynamodb,
    }
    .get_valid_token_pair(&orig)
    .await
    .context(Location::caller())?
    else {
        bail!(AuthError::Unauthorized);
    };

    if jti != valid_token_pair.access_token_jti {
        bail!(AuthError::Unauthorized);
    }

    let MethodArn { method, path, .. } = MethodArn::from(method_arn_str);

    let now = common::get_current_timestamp()
        .call()
        .context(Location::caller())?;

    if !env
        .rbac_cache
        .borrow()
        .contains_key(&format!("{method}_{path}"))
        || env.rbac_cache.borrow()[&format!("{method}_{path}")].expired_at <= now
    {
        let rbac = AuthRbacDb {
            dynamodb: &env.dynamodb,
        }
        .get_rbac(&method, &path)
        .await
        .context(Location::caller())?;

        let mut rbac_cache = env.rbac_cache.borrow_mut();

        rbac_cache.insert(
            format!("{method}_{path}"),
            AuthRbacExt {
                rbac,
                expired_at: common::extend_current_timestamp()
                    .hours(1)
                    .call()
                    .context(Location::caller())?,
            },
        );
    }

    let rbac_cache = env.rbac_cache.borrow();

    let policy_effect = if let Some(rbac) = &rbac_cache[&format!("{method}_{path}")].rbac {
        if rbac.roles.is_disjoint(&HashSet::from_iter(roles)) {
            IamPolicyEffect::Deny
        } else {
            IamPolicyEffect::Allow
        }
    } else {
        IamPolicyEffect::Deny
    };

    let policy = gen_policy(
        method_arn_str.to_string(),
        sub.to_string(),
        policy_effect,
        jti,
    )
    .sub(sub.to_string())
    .orig(orig)
    .call();

    Ok(policy)
}

async fn auth_refresh_token(
    AuthRefreshToken { jti, sub, .. }: AuthRefreshToken,
    method_arn_str: &str,
    env: &Env,
) -> Result<ApiGatewayCustomAuthorizerResponse<AuthUserContext>> {
    let Some(_valid_token_pair) = AuthValidTokenPairDb {
        dynamodb: &env.dynamodb,
    }
    .get_valid_token_pair(&jti)
    .await
    .context(Location::caller())?
    else {
        bail!(AuthError::Unauthorized);
    };

    let policy_effect = if MethodArn::from(method_arn_str).path.ends_with("/refresh") {
        IamPolicyEffect::Allow
    } else {
        IamPolicyEffect::Deny
    };

    let policy = gen_policy(
        method_arn_str.to_string(),
        jti.to_string(),
        policy_effect,
        jti,
    )
    .sub(sub.to_string())
    .call();

    Ok(policy)
}

async fn auth_session_token(
    AuthSessionToken {
        jti,
        sub,
        src,
        aud,
        dest,
        ..
    }: AuthSessionToken,
    method_arn_str: &str,
) -> ApiGatewayCustomAuthorizerResponse<AuthUserContext> {
    let policy_effect = if MethodArn::from(method_arn_str)
        .path
        .ends_with(&format!("/{aud}"))
    {
        IamPolicyEffect::Allow
    } else {
        IamPolicyEffect::Deny
    };

    gen_policy(
        method_arn_str.to_string(),
        sub.to_string(),
        policy_effect,
        jti,
    )
    .sub(sub.to_string())
    .src(src)
    .dest(dest)
    .call()
}
