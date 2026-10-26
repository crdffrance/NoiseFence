use anyhow::{Result, anyhow, ensure};
use reqwest::{
    Client, Url,
    header::{AUTHORIZATION, HeaderValue},
};
use serde::Deserialize;
use std::{collections::BTreeSet, future::Future, time::Duration};

const HOST: &str = "graph.microsoft.com";
pub(super) const PAGE_BYTES: usize = 2 * 1024 * 1024;

/// Construction is confined to approved collection endpoints. A nextLink may
/// paginate the same collection, not change the resource, query or authority.
#[derive(Clone)]
pub(super) struct Request {
    url: Url,
    path: String,
    select: BTreeSet<String>,
}
impl Request {
    pub fn collection(path: &str, select: &str) -> Result<Self> {
        let allowed = matches!(path, "/v1.0/users" | "/v1.0/groups")
            || path
                .strip_prefix("/v1.0/groups/")
                .and_then(|p| p.strip_suffix("/members"))
                .is_some_and(|id| uuid::Uuid::parse_str(id).is_ok() && id.len() == 36);
        ensure!(allowed, "Unsupported directory resource");
        let mut url = Url::parse(&format!("https://{HOST}{path}"))?;
        url.query_pairs_mut()
            .append_pair("$select", select)
            .append_pair("$top", "999");
        Ok(Self {
            url,
            path: path.into(),
            select: select.split(',').map(str::to_string).collect(),
        })
    }
    pub fn next(&self, raw: &str) -> Result<Self> {
        ensure!(
            raw.len() <= 8192 && !raw.chars().any(char::is_control),
            "Invalid directory continuation"
        );
        let url = Url::parse(raw).map_err(|_| anyhow!("Invalid directory continuation"))?;
        ensure!(
            url.scheme() == "https"
                && url.host_str() == Some(HOST)
                && url.port().is_none()
                && url.username().is_empty()
                && url.password().is_none()
                && url.fragment().is_none()
                && url.path() == self.path,
            "Directory continuation changed its authority or resource"
        );
        let mut seen = BTreeSet::new();
        let mut has_cursor = false;
        for (key, value) in url.query_pairs() {
            ensure!(
                seen.insert(key.to_ascii_lowercase()),
                "Duplicate directory query parameter"
            );
            match key.as_ref() {
                "$select" => ensure!(
                    value
                        .split(',')
                        .map(str::to_string)
                        .collect::<BTreeSet<_>>()
                        == self.select,
                    "Directory continuation changed selected properties"
                ),
                "$top" => ensure!(
                    value.parse::<usize>().is_ok_and(|n| (1..=999).contains(&n)),
                    "Invalid directory page size"
                ),
                "$skiptoken" | "$skipToken" => {
                    ensure!(!value.is_empty(), "Empty directory cursor");
                    has_cursor = true;
                }
                _ => return Err(anyhow!("Unsupported directory continuation query")),
            }
        }
        ensure!(
            has_cursor && seen.contains("$select"),
            "Directory continuation lacks its cursor or selection"
        );
        Ok(Self {
            url,
            path: self.path.clone(),
            select: self.select.clone(),
        })
    }
    pub fn identity(&self) -> &str {
        self.url.as_str()
    }
}

pub(super) struct Page {
    pub status: u16,
    pub retry_after: Option<Duration>,
    pub bytes: Vec<u8>,
}
pub(super) trait Transport: Sync {
    fn get(&self, request: &Request) -> impl Future<Output = Result<Page>> + Send;
}

// Intentionally not Debug/Serialize: neither secrets nor opaque access tokens
// belong in configuration exports, traces, source snapshots or failure messages.
pub struct Credentials {
    pub(super) tenant: uuid::Uuid,
    client: uuid::Uuid,
    secret: String,
}
impl Credentials {
    pub fn new(tenant: &str, client: &str, secret: String) -> Result<Self> {
        ensure!(
            !secret.is_empty() && secret.len() <= 4096 && !secret.chars().any(char::is_control),
            "Invalid directory credential"
        );
        let tenant =
            uuid::Uuid::parse_str(tenant).map_err(|_| anyhow!("Invalid Entra tenant ID"))?;
        let client =
            uuid::Uuid::parse_str(client).map_err(|_| anyhow!("Invalid Entra application ID"))?;
        ensure!(
            !tenant.is_nil() && !client.is_nil(),
            "Invalid Entra credential identity"
        );
        Ok(Self {
            tenant,
            client,
            secret,
        })
    }
}
pub(super) struct Http {
    client: Client,
    authorization: HeaderValue,
}
impl Http {
    pub async fn authenticate(credentials: &Credentials) -> Result<Self> {
        let client = client_builder()
            .build()
            .map_err(|_| anyhow!("Directory HTTP initialization failed"))?;
        let endpoint = format!(
            "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
            credentials.tenant
        );
        let response = client
            .post(endpoint)
            .form(&[
                ("client_id", credentials.client.to_string()),
                ("client_secret", credentials.secret.clone()),
                ("scope", "https://graph.microsoft.com/.default".to_string()),
                ("grant_type", "client_credentials".to_string()),
            ])
            .send()
            .await
            .map_err(|_| anyhow!("Directory authentication unavailable"))?;
        ensure!(
            response.status().as_u16() == 200,
            "Directory authentication refused"
        );
        let bytes = read_body(response, 64 * 1024).await?;
        #[derive(Deserialize)]
        struct Token {
            access_token: String,
            token_type: String,
            expires_in: u64,
        }
        let token: Token = serde_json::from_slice(&bytes)
            .map_err(|_| anyhow!("Invalid directory authentication response"))?;
        ensure!(
            token.token_type.eq_ignore_ascii_case("bearer")
                && (1..=86400).contains(&token.expires_in)
                && !token.access_token.is_empty()
                && token.access_token.len() <= 32768,
            "Invalid directory access token"
        );
        let mut authorization = HeaderValue::from_str(&format!("Bearer {}", token.access_token))
            .map_err(|_| anyhow!("Invalid directory access token"))?;
        authorization.set_sensitive(true);
        Ok(Self {
            client,
            authorization,
        })
    }
}
pub(super) fn client_builder() -> reqwest::ClientBuilder {
    Client::builder()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(15))
        .user_agent("NoiseFence directory connector")
}
pub(super) async fn read_body(mut response: reqwest::Response, maximum: usize) -> Result<Vec<u8>> {
    ensure!(
        response
            .content_length()
            .is_none_or(|n| n <= maximum as u64),
        "Directory response exceeds size limit"
    );
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| anyhow!("Directory response interrupted"))?
    {
        ensure!(
            bytes.len().saturating_add(chunk.len()) <= maximum,
            "Directory response exceeds size limit"
        );
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}
impl Transport for Http {
    async fn get(&self, request: &Request) -> Result<Page> {
        let response = self
            .client
            .get(request.url.clone())
            .header(AUTHORIZATION, self.authorization.clone())
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|_| anyhow!("Directory request unavailable"))?;
        let status = response.status().as_u16();
        let retry_after = response
            .headers()
            .get("retry-after")
            .and_then(|value| value.to_str().ok())
            .map(|value| {
                value
                    .parse::<u64>()
                    .ok()
                    .map(Duration::from_secs)
                    .unwrap_or(Duration::from_secs(3600))
            });
        // Error bodies and response URLs can contain private data. Never retain
        // them in a report, or follow a redirect with bearer credentials.
        let bytes = if status == 200 {
            read_body(response, PAGE_BYTES).await?
        } else {
            vec![]
        };
        Ok(Page {
            status,
            retry_after,
            bytes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn continuations_cannot_exfiltrate_credentials_or_filter_the_source() {
        let request = Request::collection("/v1.0/users", "id,displayName").unwrap();
        for url in [
            "https://attacker.test/v1.0/users?$select=id,displayName&$skiptoken=secret",
            "http://graph.microsoft.com/v1.0/users?$select=id,displayName&$skiptoken=x",
            "https://graph.microsoft.com@attacker.test/v1.0/users?$select=id,displayName&$skiptoken=x",
            "https://graph.microsoft.com:8443/v1.0/users?$select=id,displayName&$skiptoken=x",
            "https://graph.microsoft.com/v1.0/groups?$select=id,displayName&$skiptoken=x",
            "https://graph.microsoft.com/v1.0/users?$select=id,displayName&$filter=accountEnabled%20eq%20false&$skiptoken=x",
            "https://graph.microsoft.com/v1.0/users?$select=id&$skiptoken=x",
            "https://graph.microsoft.com/v1.0/users?$select=id,displayName&$skiptoken=x&$skiptoken=y",
            "https://graph.microsoft.com/v1.0/users?$select=id,displayName&$skiptoken=x#fragment",
        ] {
            let error = request.next(url).err().expect("must reject").to_string();
            assert!(!error.contains("secret"));
        }
        assert!(request.next("https://graph.microsoft.com/v1.0/users?$select=displayName,id&$top=10&$skiptoken=opaque%2bnext").is_ok());
    }
    #[test]
    fn credentials_and_resources_are_bounded() {
        assert!(Request::collection("/v1.0/me/messages", "id").is_err());
        assert!(Credentials::new("common", "123", "secret".into()).is_err());
        assert!(
            Credentials::new(
                "00000000-0000-4000-8000-000000000001",
                "00000000-0000-4000-8000-000000000002",
                "x\nsecret".into()
            )
            .is_err()
        );
    }
    async fn tls_fixture(response: String) -> (Http, Request, tokio::task::JoinHandle<String>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let _ = rustls::crypto::ring::default_provider().install_default();
        let key = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let certificate = reqwest::Certificate::from_der(key.cert.der()).unwrap();
        let config = rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![key.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(key.signing_key.serialize_der()).into(),
        )
        .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (socket, _) = tokio::time::timeout(Duration::from_secs(3), listener.accept())
                .await
                .unwrap()
                .unwrap();
            let mut tls = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(config))
                .accept(socket)
                .await
                .unwrap();
            let mut request = Vec::new();
            loop {
                request.push(tls.read_u8().await.unwrap());
                assert!(request.len() <= 8192);
                if request.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            // The receiver may deliberately close before an oversized body.
            let _ = tls.write_all(response.as_bytes()).await;
            let _ = tls.shutdown().await;
            String::from_utf8(request).unwrap()
        });
        let client = client_builder()
            .add_root_certificate(certificate)
            .build()
            .unwrap();
        let mut authorization = HeaderValue::from_static("Bearer fixture-only-token");
        authorization.set_sensitive(true);
        let http = Http {
            client,
            authorization,
        };
        // Test-only construction of a local TLS request. Production callers can
        // construct only the fixed public Graph collections above.
        let request = Request {
            url: Url::parse(&format!("https://localhost:{}/fixture", address.port())).unwrap(),
            path: "/fixture".into(),
            select: BTreeSet::new(),
        };
        (http, request, task)
    }
    #[tokio::test]
    async fn real_transport_uses_tls_and_does_not_follow_redirects_or_retain_error_bodies() {
        let other = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let response = format!(
            "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{}/leak\r\nContent-Length: 11\r\nConnection: close\r\n\r\nsecret-body",
            other.local_addr().unwrap().port()
        );
        let (http, request, task) = tls_fixture(response).await;
        let page = http.get(&request).await.unwrap();
        assert_eq!(page.status, 302);
        assert!(page.bytes.is_empty());
        assert!(
            task.await
                .unwrap()
                .contains("authorization: Bearer fixture-only-token")
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(30), other.accept())
                .await
                .is_err()
        );
    }
    #[tokio::test]
    async fn real_transport_bounds_declared_and_chunked_response_bodies() {
        for response in [
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                PAGE_BYTES + 1
            ),
            format!(
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n{}\r\n0\r\n\r\n",
                PAGE_BYTES + 1,
                "x".repeat(PAGE_BYTES + 1)
            ),
        ] {
            let (http, request, task) = tls_fixture(response).await;
            assert!(
                http.get(&request)
                    .await
                    .err()
                    .unwrap()
                    .to_string()
                    .contains("size limit")
            );
            task.await.unwrap();
        }
    }
    #[tokio::test]
    async fn real_transport_never_retries_invalid_or_long_retry_after_immediately() {
        let (http,request,task) = tls_fixture("HTTP/1.1 429 Too Many Requests\r\nRetry-After: invalid-private-value\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into()).await;
        let page = http.get(&request).await.unwrap();
        assert_eq!(page.retry_after, Some(Duration::from_secs(3600)));
        assert!(page.bytes.is_empty());
        task.await.unwrap();
    }
}
