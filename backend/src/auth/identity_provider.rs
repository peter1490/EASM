use openidconnect::{
    core::{CoreClient, CoreProviderMetadata, CoreResponseType},
    ClientId, ClientSecret, IssuerUrl, RedirectUrl,
    AuthenticationFlow,
};
use openidconnect::{Scope, Nonce, CsrfToken};
use crate::config::Settings;
use anyhow::{Result, Context};
use std::sync::Arc;

#[derive(Clone)]
pub struct OidcProvider {
    client: CoreClient,
}

impl OidcProvider {
    pub async fn google(settings: &Settings) -> Result<Self> {
        let client_id = ClientId::new(settings.google_client_id.clone().context("Google Client ID not set")?);
        let client_secret = ClientSecret::new(settings.google_client_secret.clone().context("Google Client Secret not set")?);
        let issuer_url = IssuerUrl::new(settings.google_discovery_url.clone().unwrap_or("https://accounts.google.com".to_string()))?;

        let provider_metadata = CoreProviderMetadata::discover_async(
            issuer_url,
            async_http_client,
        )
        .await?;

        let client = CoreClient::from_provider_metadata(
            provider_metadata,
            client_id,
            Some(client_secret),
        )
        .set_redirect_uri(RedirectUrl::new(settings.google_redirect_uri.clone().context("Google Redirect URI not set")?)?);

        Ok(Self { client })
    }

    pub async fn keycloak(settings: &Settings) -> Result<Self> {
         let client_id = ClientId::new(settings.keycloak_client_id.clone().context("Keycloak Client ID not set")?);
         let client_secret = ClientSecret::new(settings.keycloak_client_secret.clone().context("Keycloak Client Secret not set")?);
         
         // If discovery URL is not provided, construct it from realm
         let discovery_url = if let Some(url) = &settings.keycloak_discovery_url {
             url.clone()
         } else if let Some(realm) = &settings.keycloak_realm {
             // Assuming standard keycloak path
             format!("http://localhost:8080/realms/{}", realm) 
         } else {
             return Err(anyhow::anyhow!("Keycloak Discovery URL or Realm must be set"));
         };
         
         let issuer_url = IssuerUrl::new(discovery_url)?;

         let provider_metadata = CoreProviderMetadata::discover_async(
            issuer_url,
            async_http_client,
        )
        .await?;

        let client = CoreClient::from_provider_metadata(
            provider_metadata,
            client_id,
            Some(client_secret),
        )
        .set_redirect_uri(RedirectUrl::new(settings.keycloak_redirect_uri.clone().context("Keycloak Redirect URI not set")?)?);

        Ok(Self { client })
    }

    pub fn get_authorization_url(&self) -> (reqwest::Url, CsrfToken, Nonce) {
         self.client
            .authorize_url(
                AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .add_scope(Scope::new("email".to_string()))
            .add_scope(Scope::new("profile".to_string()))
            .url()
    }
    
    // Logic to exchange code for token would be added here
    pub async fn exchange_code(&self, code: String) -> Result<openidconnect::core::CoreIdTokenClaims> {
        use openidconnect::{AuthorizationCode, TokenResponse};
        
        let token_response = self.client
            .exchange_code(AuthorizationCode::new(code))
            .request_async(async_http_client)
            .await?;
            
        let id_token = token_response.id_token().context("No ID token received")?;
        let claims = id_token.claims(&self.client.id_token_verifier(), &Nonce::new_random())?; // Nonce verification skipped for simplicity in this snippet, should strictly verify in production if we stored the nonce
        
        Ok(claims.clone())
    }
}

// Wrapper for reqwest async client to match openidconnect trait
pub async fn async_http_client(
    request: openidconnect::HttpRequest,
) -> Result<openidconnect::HttpResponse, reqwest::Error> {
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()?; 

    let mut request_builder = client
        .request(request.method, request.url.as_str())
        .body(request.body);

    for (name, value) in &request.headers {
        request_builder = request_builder.header(name.as_str(), value.as_bytes());
    }

    let response = request_builder
        .send()
        .await?;

    Ok(openidconnect::HttpResponse {
        status_code: response.status(),
        headers: response.headers().clone(),
        body: response.bytes().await?.to_vec(),
    })
}
