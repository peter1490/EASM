use crate::error::ApiError;
use governor::{Quota, RateLimiter};
use reqwest::{Client, Response};
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;

/// Rate-limited HTTP client for external API integrations
pub struct RateLimitedClient {
    client: Client,
    rate_limiter: Arc<RateLimiter<governor::state::direct::NotKeyed, governor::state::InMemoryState, governor::clock::DefaultClock>>,
    max_retries: u32,
    base_delay: Duration,
}

impl RateLimitedClient {
    /// Create a new rate-limited client
    pub fn new(requests_per_second: u32, max_retries: u32) -> Result<Self, ApiError> {
        let quota = Quota::per_second(
            NonZeroU32::new(requests_per_second)
                .ok_or_else(|| ApiError::Validation("requests_per_second must be greater than 0".to_string()))?
        );
        
        let rate_limiter = Arc::new(RateLimiter::direct(quota));
        
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("EASM-Rust-Backend/1.0")
            .build()?;

        Ok(Self {
            client,
            rate_limiter,
            max_retries,
            base_delay: Duration::from_millis(1000),
        })
    }

    /// Make a rate-limited GET request with retries
    pub async fn get(&self, url: &str) -> Result<Response, ApiError> {
        self.make_request(|client| client.get(url)).await
    }

    /// Make a rate-limited GET request with custom headers
    pub async fn get_with_headers(&self, url: &str, headers: reqwest::header::HeaderMap) -> Result<Response, ApiError> {
        self.make_request(|client| client.get(url).headers(headers.clone())).await
    }

    /// Make a rate-limited POST request with retries
    pub async fn post(&self, url: &str) -> Result<reqwest::RequestBuilder, ApiError> {
        // Wait for rate limit
        self.rate_limiter.until_ready().await;
        Ok(self.client.post(url))
    }

    /// Internal method to make requests with rate limiting and retries
    async fn make_request<F>(&self, request_builder: F) -> Result<Response, ApiError>
    where
        F: Fn(&Client) -> reqwest::RequestBuilder + Clone,
    {
        let mut last_error = None;

        for attempt in 0..=self.max_retries {
            // Wait for rate limit
            self.rate_limiter.until_ready().await;

            match request_builder(&self.client).send().await {
                Ok(response) => {
                    if response.status().is_success() {
                        return Ok(response);
                    } else if response.status().is_server_error() && attempt < self.max_retries {
                        // Retry on server errors
                        let delay = self.base_delay * 2_u32.pow(attempt);
                        tracing::warn!(
                            "Server error {} on attempt {}, retrying in {:?}",
                            response.status(),
                            attempt + 1,
                            delay
                        );
                        sleep(delay).await;
                        continue;
                    } else {
                        // Client error or final server error
                        let status = response.status();
                        let body = response.text().await.unwrap_or_default();
                        return Err(ApiError::ExternalService(format!(
                            "HTTP {} error: {}",
                            status, body
                        )));
                    }
                }
                Err(e) => {
                    last_error = Some(e);
                    if attempt < self.max_retries {
                        let delay = self.base_delay * 2_u32.pow(attempt);
                        tracing::warn!(
                            "Request failed on attempt {}, retrying in {:?}: {}",
                            attempt + 1,
                            delay,
                            last_error.as_ref().unwrap()
                        );
                        sleep(delay).await;
                    }
                }
            }
        }

        Err(ApiError::HttpClient(last_error.unwrap()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::{matchers::method, Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn test_rate_limited_client_success() {
        let mock_server = MockServer::start().await;
        
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string("success"))
            .mount(&mock_server)
            .await;

        let client = RateLimitedClient::new(10, 3).unwrap();
        let response = client.get(&mock_server.uri()).await.unwrap();
        
        assert!(response.status().is_success());
        let body = response.text().await.unwrap();
        assert_eq!(body, "success");
    }

    #[tokio::test]
    async fn test_rate_limited_client_retry_on_server_error() {
        let mock_server = MockServer::start().await;
        
        // First request fails with 500, second succeeds
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(500))
            .up_to_n_times(1)
            .mount(&mock_server)
            .await;
            
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string("success"))
            .mount(&mock_server)
            .await;

        let client = RateLimitedClient::new(10, 3).unwrap();
        let response = client.get(&mock_server.uri()).await.unwrap();
        
        assert!(response.status().is_success());
    }

    #[tokio::test]
    async fn test_rate_limited_client_client_error() {
        let mock_server = MockServer::start().await;
        
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(404).set_body_string("not found"))
            .mount(&mock_server)
            .await;

        let client = RateLimitedClient::new(10, 3).unwrap();
        let result = client.get(&mock_server.uri()).await;
        
        assert!(result.is_err());
        match result.unwrap_err() {
            ApiError::ExternalService(msg) => assert!(msg.contains("404")),
            _ => panic!("Expected ExternalService error"),
        }
    }
}