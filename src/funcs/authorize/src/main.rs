use anyhow::{bail, Context as _, Result};
use auth_lib::{
    auth_constants,
    auth_enums::{Action, JwtToken},
    auth_jwt::{AuthAccessToken, AuthRefreshToken, AuthSessionToken},
    AuthError, AuthRbacDb, AuthUserContext, AuthValidTokenPairDb,
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
use serde_json::{Map, Value};
use std::{collections::HashSet, mem, panic::Location};

#[derive(Debug)]
struct Env {
    dynamodb: aws_sdk_dynamodb::Client,
    access_token_secret: String,
    refresh_token_secret: String,
    session_token_secret: String,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Error> {
    common_tracing::init();

    let config = aws_config::load_defaults(BehaviorVersion::latest()).await;
    let dynamodb = aws_sdk_dynamodb::Client::new(&config);
    let ssm = aws_sdk_ssm::Client::new(&config);

    let [access_token_secret, refresh_token_secret, session_token_secret] = ssm
        .get_parameters_by_path()
        .path(auth_constants::JWT_TOKEN_PARAM_PATH)
        .recursive(false)
        .with_decryption(true)
        .send()
        .await?
        .parameters
        .unwrap()
        .try_into()
        .unwrap();

    let env = Env {
        dynamodb,
        access_token_secret: access_token_secret.value.unwrap(),
        refresh_token_secret: refresh_token_secret.value.unwrap(),
        session_token_secret: session_token_secret.value.unwrap(),
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
                    Ok(Value::String("unauthorized".to_string()))
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

    // Find the type of this JWT token
    let jwt_token = match jsonwebtoken::decode::<Value>(
        jwt_token,
        &DecodingKey::from_secret(&[]),
        &disabled_validation,
    )?
    .claims
    .as_object()
    .unwrap_or(&Map::new())
    .get("typ")
    {
        Some(Value::String(typ)) => {
            let mut validation = Validation::new(Algorithm::HS512);
            validation.set_audience(auth_constants::AUDIENCE_ACTIONS);

            // Ensure the given JWT token is valid
            match typ.as_str() {
                auth_constants::TOKEN_TYPE_ACCESS => {
                    let jwt_token = jsonwebtoken::decode(
                        jwt_token,
                        &DecodingKey::from_secret(env.access_token_secret.as_bytes()),
                        &validation,
                    )?;

                    JwtToken::Access(jwt_token.claims)
                }
                auth_constants::TOKEN_TYPE_REFRESH => {
                    let jwt_token = jsonwebtoken::decode(
                        jwt_token,
                        &DecodingKey::from_secret(env.refresh_token_secret.as_bytes()),
                        &validation,
                    )?;

                    JwtToken::Refresh(jwt_token.claims)
                }
                auth_constants::TOKEN_TYPE_SESSION => {
                    let jwt_token = jsonwebtoken::decode(
                        jwt_token,
                        &DecodingKey::from_secret(env.session_token_secret.as_bytes()),
                        &validation,
                    )?;

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
    #[optarg_default] name: String,
    #[optarg_default] dest: Option<Action>,
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
            name,
            dest,
        },
        usage_identifier_key: None,
    }
}

async fn auth_access_token(
    mut access_token: AuthAccessToken,
    method_arn_str: &str,
    env: &Env,
) -> Result<ApiGatewayCustomAuthorizerResponse<AuthUserContext>> {
    let valid_token_pair = AuthValidTokenPairDb {
        dynamodb: &env.dynamodb,
    }
    .get_item(&access_token.orig)
    .await
    .context(Location::caller())?;

    if valid_token_pair.is_none() || access_token.jti != valid_token_pair.unwrap().access_token_jti
    {
        bail!(AuthError::Unauthorized);
    }

    let method_arn = MethodArn::from(method_arn_str);

    let rbac = AuthRbacDb {
        dynamodb: &env.dynamodb,
    }
    .get_item(&method_arn.method, &method_arn.path)
    .await
    .context(Location::caller())?;

    let policy_effect = if rbac.is_none()
        || rbac
            .unwrap()
            .roles
            .is_disjoint(&HashSet::from_iter(mem::take(&mut access_token.roles)))
    {
        IamPolicyEffect::Deny
    } else {
        IamPolicyEffect::Allow
    };

    let policy = gen_policy(
        method_arn_str.to_string(),
        access_token.name.to_string(),
        policy_effect,
        mem::take(&mut access_token.jti),
    )
    .sub(mem::take(&mut access_token.sub))
    .name(mem::take(&mut access_token.name))
    .call();

    Ok(policy)
}

async fn auth_refresh_token(
    mut refresh_token: AuthRefreshToken,
    method_arn_str: &str,
    env: &Env,
) -> Result<ApiGatewayCustomAuthorizerResponse<AuthUserContext>> {
    let valid_token_pair = AuthValidTokenPairDb {
        dynamodb: &env.dynamodb,
    }
    .get_item(&refresh_token.jti)
    .await
    .context(Location::caller())?;

    if valid_token_pair.is_none() {
        bail!(AuthError::Unauthorized);
    }

    let policy_effect = if MethodArn::from(method_arn_str).path.ends_with("/refresh") {
        IamPolicyEffect::Allow
    } else {
        IamPolicyEffect::Deny
    };

    let policy = gen_policy(
        method_arn_str.to_string(),
        refresh_token.jti.to_string(),
        policy_effect,
        mem::take(&mut refresh_token.jti),
    )
    .call();

    Ok(policy)
}

async fn auth_session_token(
    mut session_token: AuthSessionToken,
    method_arn_str: &str,
) -> ApiGatewayCustomAuthorizerResponse<AuthUserContext> {
    let policy_effect = if MethodArn::from(method_arn_str)
        .path
        .ends_with(&format!("/{aud}", aud = session_token.aud))
    {
        IamPolicyEffect::Allow
    } else {
        IamPolicyEffect::Deny
    };

    gen_policy(
        method_arn_str.to_string(),
        session_token.name.to_string(),
        policy_effect,
        mem::take(&mut session_token.jti),
    )
    .sub(mem::take(&mut session_token.sub))
    .name(mem::take(&mut session_token.name))
    .dest(session_token.dest)
    .call()
}
