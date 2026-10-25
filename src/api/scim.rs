//! Inbound directory staging, never console authentication or SMTP policy.
mod discovery;
use super::{App, Json};
use crate::identity::{
    directory::Source,
    scim::{self, Command, Reply, ResourceType, access::Access},
};
use axum::{
    Router,
    body::Body,
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::any,
};
use serde_json::Value;
use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
const UNAUTHORIZED: scim::Error = scim::Error::new(401, "", "Invalid provisioning authorization.");
const INVALID: scim::Error = scim::Error::new(
    400,
    "invalidSyntax",
    "Invalid or unsupported provisioning request.",
);
const UNAVAILABLE: scim::Error = scim::Error::new(
    503,
    "",
    "Provisioning temporarily unavailable. Read current resource state before retrying an uncertain write.",
);
const NOT_FOUND: scim::Error =
    scim::Error::new(404, "", "Provisioning endpoint or resource not found.");
const BUSY: scim::Error = scim::Error::new(429, "", "Provisioning capacity reached; retry later.");
#[derive(Clone)]
pub(super) struct Admission {
    capacity: Arc<tokio::sync::Semaphore>,
    window: Arc<Mutex<(Instant, u32)>>,
}
impl Admission {
    pub fn new() -> Self {
        Self {
            capacity: Arc::new(tokio::sync::Semaphore::new(4)),
            window: Arc::new(Mutex::new((Instant::now(), 0))),
        }
    }
    fn acquire(&self) -> scim::Result<tokio::sync::OwnedSemaphorePermit> {
        let mut window = self.window.lock().map_err(|_| UNAVAILABLE)?;
        if window.0.elapsed() >= Duration::from_secs(60) {
            *window = (Instant::now(), 0);
        }
        if window.1 >= 1200 {
            return Err(BUSY);
        }
        window.1 += 1;
        self.capacity.clone().try_acquire_owned().map_err(|_| BUSY)
    }
}
pub(super) fn routes() -> Router<App> {
    Router::new()
        .route("/scim", any(entry))
        .route("/scim/{*path}", any(entry))
}
fn failure(e: scim::Error) -> Response {
    let mut result = (
        StatusCode::from_u16(e.status).unwrap_or(StatusCode::SERVICE_UNAVAILABLE),
        Json(e.body()),
    )
        .into_response();
    result.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/scim+json"),
    );
    if e.status == 401 {
        result.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_static(r#"Bearer realm="NoiseFence provisioning""#),
        );
    }
    if e.status == 429 || e.status == 503 {
        result
            .headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static("60"));
    }
    result
}
fn method_not_allowed(allowed: &'static str) -> Response {
    let mut response = failure(scim::Error::new(
        405,
        "",
        "Unsupported method for this provisioning endpoint.",
    ));
    response
        .headers_mut()
        .insert(header::ALLOW, HeaderValue::from_static(allowed));
    response
}
fn storage(e: anyhow::Error) -> scim::Error {
    e.downcast_ref::<scim::Error>()
        .copied()
        .unwrap_or(UNAVAILABLE)
}
fn one<'a>(h: &'a HeaderMap, name: &str) -> scim::Result<Option<&'a str>> {
    let mut values = h.get_all(name).iter();
    let value = values
        .next()
        .map(|v| v.to_str().map_err(|_| INVALID))
        .transpose()?;
    if values.next().is_some() {
        return Err(INVALID);
    }
    Ok(value)
}
fn authorization(h: &mut HeaderMap) -> scim::Result<String> {
    let raw = one(h, "authorization")
        .map_err(|_| UNAUTHORIZED)?
        .ok_or(UNAUTHORIZED)?;
    let (scheme, value) = raw.split_once(' ').ok_or(UNAUTHORIZED)?;
    if !scheme.eq_ignore_ascii_case("Bearer") || value.len() != 109 {
        return Err(UNAUTHORIZED);
    }
    let token = value.to_owned();
    if let Some(value) = h.get_mut(header::AUTHORIZATION) {
        value.set_sensitive(true);
    }
    Ok(token)
}
async fn entry(State(app): State<App>, mut request: Request) -> Response {
    let head = request.method() == axum::http::Method::HEAD;
    let response = match app.scim_admission.acquire() {
        Err(e) => failure(e),
        Ok(permit) => {
            // The permit survives a disconnected client until body reading and
            // the bounded database operation have actually finished.
            match tokio::spawn(async move {
                let _permit = permit;
                handle(app, &mut request).await.unwrap_or_else(failure)
            })
            .await
            {
                Ok(response) => response,
                Err(_) => failure(UNAVAILABLE),
            }
        }
    };
    let mut response = response;
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(header::VARY, HeaderValue::from_static("Authorization"));
    if head {
        *response.body_mut() = Body::empty();
    }
    response
}
fn scope(app: &App, source: &Source) -> scim::Result<()> {
    let config = app.effective();
    if app.control.is_none()
        || !source
            .scopes
            .iter()
            .all(|s| config.domains.iter().any(|d| &d.name == s))
    {
        return Err(scim::Error::new(
            403,
            "",
            "Provisioning source is not authorized for the current configuration.",
        ));
    }
    Ok(())
}
fn decode(s: &str, form: bool) -> scim::Result<String> {
    let mut out = Vec::with_capacity(s.len());
    let mut i = 0;
    let bytes = s.as_bytes();
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return Err(INVALID);
            }
            let hex = |b: u8| (b as char).to_digit(16).map(|n| n as u8).ok_or(INVALID);
            out.push((hex(bytes[i + 1])? << 4) | hex(bytes[i + 2])?);
            i += 3;
        } else {
            out.push(if form && bytes[i] == b'+' {
                b' '
            } else {
                bytes[i]
            });
            i += 1;
        }
    }
    let value = String::from_utf8(out).map_err(|_| INVALID)?;
    if value.chars().any(char::is_control) {
        return Err(INVALID);
    }
    Ok(value)
}
fn query(raw: Option<&str>) -> scim::Result<Vec<(String, String)>> {
    let Some(raw) = raw.filter(|r| !r.is_empty()) else {
        return Ok(vec![]);
    };
    if raw.len() > 4096 {
        return Err(INVALID);
    }
    let mut pairs = Vec::new();
    for part in raw.split('&') {
        if pairs.len() == 3 {
            return Err(INVALID);
        }
        let (key, value) = part.split_once('=').ok_or(INVALID)?;
        pairs.push((decode(key, true)?, decode(value, true)?));
    }
    Ok(pairs)
}
fn media(h: &HeaderMap) -> scim::Result<()> {
    let raw = one(h, "content-type")?.ok_or(scim::Error::new(
        415,
        "",
        "A JSON content type is required.",
    ))?;
    let mut parts = raw.split(';');
    if !["application/scim+json", "application/json"]
        .iter()
        .any(|v| {
            parts
                .clone()
                .next()
                .unwrap_or("")
                .trim()
                .eq_ignore_ascii_case(v)
        })
    {
        return Err(scim::Error::new(
            415,
            "",
            "Unsupported provisioning content type.",
        ));
    }
    parts.next();
    for part in parts {
        let (key, value) = part.trim().split_once('=').ok_or(INVALID)?;
        if !key.eq_ignore_ascii_case("charset")
            || !value.trim_matches('"').eq_ignore_ascii_case("utf-8")
        {
            return Err(INVALID);
        }
    }
    Ok(())
}
fn conditional(h: &HeaderMap, name: &str) -> scim::Result<Option<String>> {
    let value = one(h, name)?;
    if value.is_some_and(|v| {
        v.len() > 100
            || v.contains(',')
            || !(v == "*" || (v.starts_with("W/\"") && v.ends_with('"')))
    }) {
        return Err(INVALID);
    }
    Ok(value.map(str::to_owned))
}
fn json_response(status: StatusCode, value: Value) -> Response {
    let mut response = (status, Json(value)).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/scim+json"),
    );
    response
}
async fn handle(app: App, request: &mut Request) -> scim::Result<Response> {
    let token = authorization(request.headers_mut())?;
    let path = request.uri().path().to_owned();
    let parts: Vec<_> = path.split('/').collect();
    if !(5..=6).contains(&parts.len())
        || parts[1] != "scim"
        || !scim::endpoint::source_id(parts[2])
        || parts[3] != "v2"
    {
        return Err(NOT_FOUND);
    }
    let source_id = parts[2];
    let base = scim::endpoint::base(
        &app.config.web.public_origin,
        source_id,
        !app.config.web.secure_cookies && app.config.web.listen.ip().is_loopback(),
    )?;
    if app.control.is_none() {
        return Err(UNAVAILABLE);
    }
    let access = Access::new(source_id.into(), token)?;
    let (access, source) = app.store.scim_preflight(access).await.map_err(storage)?;
    scope(&app, &source)?;
    let args = query(request.uri().query())?;
    if one(request.headers(), "content-encoding")?
        .is_some_and(|v| !v.eq_ignore_ascii_case("identity"))
    {
        return Err(scim::Error::new(
            415,
            "",
            "Encoded provisioning bodies are unsupported.",
        ));
    }
    let method = request.method().as_str().to_owned();
    let read = method == "GET" || method == "HEAD";
    let expected = conditional(request.headers(), "if-match")?;
    let none = conditional(request.headers(), "if-none-match")?;
    if (read && expected.is_some()) || (!read && none.is_some()) {
        return Err(INVALID);
    }
    let endpoint = parts[4];
    let id = parts.get(5).map(|s| decode(s, false)).transpose()?;
    if ["ServiceProviderConfig", "ResourceTypes", "Schemas"].contains(&endpoint) {
        if !read {
            return Ok(method_not_allowed("GET, HEAD"));
        }
        if expected.is_some() || none.is_some() {
            return Err(INVALID);
        }
        let data = discovery::get(&base, endpoint, id.as_deref(), &args)?;
        scope(&app, &source)?;
        app.store
            .scim_request(access, Command::Authenticate)
            .await
            .map_err(storage)?;
        return Ok(json_response(StatusCode::OK, data));
    }
    let kind = match endpoint {
        "Users" => ResourceType::User,
        "Groups" => ResourceType::Group,
        _ => return Err(NOT_FOUND),
    };
    if (id.is_some() || !read) && !args.is_empty() {
        return Err(INVALID);
    }
    if id.is_none() && (expected.is_some() || none.is_some()) {
        return Err(INVALID);
    }
    let allowed = if id.is_some() {
        "GET, HEAD, PUT, PATCH, DELETE"
    } else {
        "GET, HEAD, POST"
    };
    let create = method == "POST" && id.is_none();
    let body = if create || ((method == "PUT" || method == "PATCH") && id.is_some()) {
        media(request.headers())?;
        let body = std::mem::replace(request.body_mut(), Body::empty());
        tokio::time::timeout(
            Duration::from_secs(10),
            axum::body::to_bytes(body, scim::MAX_BODY_BYTES),
        )
        .await
        .map_err(|_| scim::Error::new(408, "", "Provisioning body timed out."))?
        .map_err(|_| {
            scim::Error::new(
                413,
                "tooMany",
                "Provisioning body exceeds 1 MiB or cannot be read.",
            )
        })?
        .to_vec()
    } else {
        vec![]
    };
    let command = match (method.as_str(), id) {
        ("GET" | "HEAD", Some(id)) => Command::Get { kind, id },
        ("GET" | "HEAD", None) => Command::List {
            kind,
            query: scim::ListQuery::parse(kind, &args)?,
        },
        ("POST", None) => Command::Create { kind, body },
        ("PUT", Some(id)) => Command::Replace {
            kind,
            id,
            body,
            expected,
        },
        ("PATCH", Some(id)) => Command::Patch {
            kind,
            id,
            body,
            expected,
        },
        ("DELETE", Some(id)) => Command::Delete { kind, id, expected },
        _ => return Ok(method_not_allowed(allowed)),
    };
    scope(&app, &source)?;
    match app
        .store
        .scim_request(access, command)
        .await
        .map_err(storage)?
    {
        Reply::Resource(resource) => {
            let etag = resource.etag();
            let location = format!("{base}/{}/{}", kind.endpoint(), resource.id());
            let mut response = if none.as_deref().is_some_and(|v| v == "*" || v == etag) {
                StatusCode::NOT_MODIFIED.into_response()
            } else {
                let mut value = resource.document();
                value["meta"]["location"] = Value::String(location.clone());
                json_response(
                    if create {
                        StatusCode::CREATED
                    } else {
                        StatusCode::OK
                    },
                    value,
                )
            };
            response.headers_mut().insert(
                header::ETAG,
                HeaderValue::from_str(&etag).map_err(|_| UNAVAILABLE)?,
            );
            response.headers_mut().insert(
                header::LOCATION,
                HeaderValue::from_str(&location).map_err(|_| UNAVAILABLE)?,
            );
            Ok(response)
        }
        Reply::List(mut value) => {
            if let Some(rows) = value["Resources"].as_array_mut() {
                for row in rows {
                    let id = row["id"].as_str().ok_or(UNAVAILABLE)?;
                    row["meta"]["location"] =
                        Value::String(format!("{base}/{}/{id}", kind.endpoint()));
                }
            }
            Ok(json_response(StatusCode::OK, value))
        }
        Reply::Deleted => Ok(StatusCode::NO_CONTENT.into_response()),
        Reply::Status(_) => Err(UNAVAILABLE),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn admission_limits_anonymous_traffic_and_releases_only_owned_slots() {
        let admission = Admission::new();
        let held = (0..4)
            .map(|_| admission.acquire().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(admission.acquire().unwrap_err().status, 429);
        drop(held);
        for _ in 5..1200 {
            drop(admission.acquire().unwrap());
        }
        assert_eq!(admission.acquire().unwrap_err().status, 429);
        admission.window.lock().unwrap().0 = Instant::now() - Duration::from_secs(61);
        assert!(admission.acquire().is_ok());
    }
}
