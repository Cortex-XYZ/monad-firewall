use std::net::Ipv4Addr;
use std::sync::{Arc, PoisonError};
use std::time::Duration;

use axum::{
    extract::{DefaultBodyLimit, Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

#[cfg(feature = "aya-backend")]
pub mod aya_backend;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    pub ip: Ipv4Addr,
    pub port: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SourceCounter {
    pub ip: Ipv4Addr,
    pub packets: u64,
    pub dropped: u64,
}

/// Errors
#[derive(Debug, thiserror::Error)]
pub enum FirewallError {
    #[error("operation not supported: {0}")]
    Unsupported(&'static str),
    #[error("rule not found")]
    NotFound,

    /// A lower-level backend, IO, or eBPF failure.
    #[error(transparent)]
    Backend(#[from] anyhow::Error),
}

pub trait FirewallState: Send + Sync + 'static {
    fn list_rules(&self) -> Result<Vec<Rule>, FirewallError>;
    fn add_rule(&self, rule: Rule) -> Result<(), FirewallError>;
    fn remove_rule(&self, rule: &Rule) -> Result<(), FirewallError>;
    fn counters(&self) -> Result<Vec<SourceCounter>, FirewallError>;
}

pub type SharedState = Arc<dyn FirewallState>;

#[derive(Default)]
pub struct MockFirewallState {
    inner: std::sync::Mutex<MockInner>,
}

#[derive(Default)]
struct MockInner {
    rules: Vec<Rule>,
    counters: Vec<SourceCounter>,
}

impl MockFirewallState {
    #[must_use]
    pub fn seeded() -> Self {
        let inner = MockInner {
            rules: vec![
                Rule {
                    ip: Ipv4Addr::LOCALHOST,
                    port: 8080,
                },
                Rule {
                    ip: Ipv4Addr::LOCALHOST,
                    port: 8000,
                },
            ],
            counters: vec![SourceCounter {
                ip: Ipv4Addr::new(10, 0, 0, 7),
                packets: 4_200,
                dropped: 12,
            }],
        };
        Self {
            inner: std::sync::Mutex::new(inner),
        }
    }

    /// Recover from a poisoned lock instead of panicking
    fn lock(&self) -> std::sync::MutexGuard<'_, MockInner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl FirewallState for MockFirewallState {
    fn list_rules(&self) -> Result<Vec<Rule>, FirewallError> {
        Ok(self.lock().rules.clone())
    }

    fn add_rule(&self, rule: Rule) -> Result<(), FirewallError> {
        let mut inner = self.lock();
        if !inner.rules.contains(&rule) {
            inner.rules.push(rule);
        }
        Ok(())
    }

    fn remove_rule(&self, rule: &Rule) -> Result<(), FirewallError> {
        self.lock().rules.retain(|r| r != rule);
        Ok(())
    }

    fn counters(&self) -> Result<Vec<SourceCounter>, FirewallError> {
        Ok(self.lock().counters.clone())
    }
}

#[derive(Serialize)]
struct Status {
    status: &'static str,
}

async fn healthz() -> Json<Status> {
    Json(Status { status: "ok" })
}

async fn readyz() -> Json<Status> {
    // NOTE: this is a stub
    Json(Status { status: "ready" })
}

async fn list_rules(State(state): State<SharedState>) -> Result<Json<Vec<Rule>>, FirewallError> {
    Ok(Json(state.list_rules()?))
}

async fn add_rule(
    State(state): State<SharedState>,
    Json(rule): Json<Rule>,
) -> Result<StatusCode, FirewallError> {
    state.add_rule(rule)?;
    Ok(StatusCode::CREATED)
}

async fn remove_rule(
    State(state): State<SharedState>,
    Path((ip, port)): Path<(Ipv4Addr, u16)>,
) -> Result<StatusCode, FirewallError> {
    state.remove_rule(&Rule { ip, port })?;
    Ok(StatusCode::NO_CONTENT)
}

async fn counters(
    State(state): State<SharedState>,
) -> Result<Json<Vec<SourceCounter>>, FirewallError> {
    Ok(Json(state.counters()?))
}


pub fn app(state: SharedState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/api/rules", get(list_rules).post(add_rule))
        .route("/api/rules/{ip}/{port}", axum::routing::delete(remove_rule))
        .route("/api/counters", get(counters))
        .layer(DefaultBodyLimit::max(64 * 1024))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(15),
        ))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

impl IntoResponse for FirewallError {
    fn into_response(self) -> Response {
        match self {
            FirewallError::Unsupported(what) => (
                StatusCode::NOT_IMPLEMENTED,
                format!("not supported: {what}"),
            )
                .into_response(),
            FirewallError::NotFound => (StatusCode::NOT_FOUND, "rule not found").into_response(),
            FirewallError::Backend(err) => {
                tracing::error!("backend error: {err:#}");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use tower::ServiceExt;

    fn test_app() -> Router {
        app(Arc::new(MockFirewallState::seeded()))
    }

    fn get(uri: &str) -> Request<Body> {
        Request::builder().uri(uri).body(Body::empty()).unwrap()
    }

    fn post_rule(json: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/api/rules")
            .header("content-type", "application/json")
            .body(Body::from(json.to_owned()))
            .unwrap()
    }

    fn delete(uri: &str) -> Request<Body> {
        Request::builder()
            .method("DELETE")
            .uri(uri)
            .body(Body::empty())
            .unwrap()
    }

    async fn rules_of(app: &Router) -> Vec<Rule> {
        let res = app.clone().oneshot(get("/api/rules")).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let bytes = to_bytes(res.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn healthz_returns_ok() {
        let res = test_app().oneshot(get("/healthz")).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn readyz_returns_ok() {
        let res = test_app().oneshot(get("/readyz")).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn list_rules_returns_the_seeded_rules() {
        let rules = rules_of(&test_app()).await;
        assert_eq!(rules.len(), 2);
        assert!(rules.contains(&Rule {
            ip: Ipv4Addr::LOCALHOST,
            port: 8080
        }));
        assert!(rules.contains(&Rule {
            ip: Ipv4Addr::LOCALHOST,
            port: 8000
        }));
    }

    #[tokio::test]
    async fn counters_returns_the_seeded_counter() {
        let res = test_app().oneshot(get("/api/counters")).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let bytes = to_bytes(res.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json.as_array().unwrap().len(), 1);
        assert_eq!(json[0]["ip"], "10.0.0.7");
        assert_eq!(json[0]["packets"], 4200);
        assert_eq!(json[0]["dropped"], 12);
    }

    #[tokio::test]
    async fn add_rule_persists_and_is_returned() {
        let app = test_app();
        let res = app
            .clone()
            .oneshot(post_rule(r#"{"ip":"192.168.1.5","port":443}"#))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::CREATED);

        let rules = rules_of(&app).await;
        assert!(rules.contains(&Rule {
            ip: Ipv4Addr::new(192, 168, 1, 5),
            port: 443
        }));
    }

    #[tokio::test]
    async fn add_rule_is_idempotent() {
        let app = test_app();
        let dup = r#"{"ip":"127.0.0.1","port":8080}"#;
        app.clone().oneshot(post_rule(dup)).await.unwrap();
        app.clone().oneshot(post_rule(dup)).await.unwrap();

        let rules = rules_of(&app).await;
        assert_eq!(rules.len(), 2, "a duplicate insert must not grow the list");
    }

    #[tokio::test]
    async fn remove_rule_deletes_it() {
        let app = test_app();
        let res = app
            .clone()
            .oneshot(delete("/api/rules/127.0.0.1/8080"))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::NO_CONTENT);

        let rules = rules_of(&app).await;
        assert!(!rules.contains(&Rule {
            ip: Ipv4Addr::LOCALHOST,
            port: 8080
        }));
        assert_eq!(rules.len(), 1);
    }

    #[tokio::test]
    async fn add_rule_rejects_missing_field() {
        let res = test_app()
            .oneshot(post_rule(r#"{"ip":"192.168.1.5"}"#))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn add_rule_rejects_malformed_ip() {
        let res = test_app()
            .oneshot(post_rule(r#"{"ip":"not-an-ip","port":443}"#))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn remove_rule_rejects_malformed_ip_in_path() {
        let res = test_app()
            .oneshot(delete("/api/rules/not-an-ip/8080"))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }
}
