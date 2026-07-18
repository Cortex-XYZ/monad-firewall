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

use monad_firewall_common::AllowEntry;

#[cfg(feature = "aya-backend")]
pub mod aya_backend;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    pub ip: Ipv4Addr,
    pub port: u16,
}

impl From<AllowEntry> for Rule {
    fn from(entry: AllowEntry) -> Self {
        Rule {
            ip: Ipv4Addr::from(entry.ip),
            port: entry.port,
        }
    }
}

impl From<Rule> for AllowEntry {
    fn from(rule: Rule) -> Self {
        AllowEntry {
            ip: u32::from(rule.ip),
            port: rule.port,
        }
    }
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
    #[cfg(feature = "aya-backend")]
    #[error("failed to read/write eBPF map: {0}")]
    Map(#[from] aya::maps::MapError),
    #[cfg(feature = "aya-backend")]
    #[error("failed to load pinned map: {0}")]
    Pin(#[from] std::io::Error),
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

async fn health() -> Json<Status> {
    Json(Status { status: "ok" })
}

async fn ready() -> Json<Status> {
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
        .route("/health", get(health))
        .route("/ready", get(ready))
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
            #[cfg(feature = "aya-backend")]
            FirewallError::Map(err) => {
                tracing::error!("map error: {err}");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
            }
            #[cfg(feature = "aya-backend")]
            FirewallError::Pin(err) => {
                tracing::error!("pin error: {err}");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
            }
        }
    }
}
