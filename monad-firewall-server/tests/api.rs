use std::net::Ipv4Addr;
use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use axum::Router;
use monad_firewall_server::{app, MockFirewallState, Rule};
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
async fn health_returns_ok() {
    let res = test_app().oneshot(get("/health")).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn ready_returns_ok() {
    let res = test_app().oneshot(get("/ready")).await.unwrap();
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
