use axum::{extract::{State, Request}, http::HeaderMap};
use axum::{middleware::Next, response::{IntoResponse, Response}};
use axum::http::Method as AxumMethod;
use std::collections::HashMap;
use std::sync::Arc;

use crate::{app_state::AppState, api_errors::AppError, loa::LOA, security::extract_current_user};

/// Static LOA policy mapping per route path (prefix match) and method.
/// This intentionally keeps policy simple and explicit for MVP.
pub struct LoaPolicyTable {
    /// map of (method, path_prefix) -> required LOA
    routes: HashMap<(MethodKey, &'static str), LOA>,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum MethodKey {
    Get,
    Post,
}

impl LoaPolicyTable {
    pub fn mvp_defaults() -> Self {
        let mut routes: HashMap<(MethodKey, &'static str), LOA> = HashMap::new();
        // License endpoints
        routes.insert((MethodKey::Post, "/api/license/create"), LOA::Root);
        routes.insert((MethodKey::Post, "/api/license/bootstrap"), LOA::Root);
        routes.insert((MethodKey::Post, "/api/license/validate"), LOA::Observer);

        // Quorum/system endpoints
        routes.insert((MethodKey::Post, "/api/canon/system/commit"), LOA::Root);
        routes.insert((MethodKey::Post, "/api/canon/system/propose"), LOA::Root);
        routes.insert((MethodKey::Post, "/api/canon/system/attest"), LOA::Root);

        // Memory/RAG
        routes.insert((MethodKey::Post, "/api/memory/write"), LOA::Operator);
        routes.insert((MethodKey::Get, "/api/memory/list"), LOA::Observer);
        routes.insert((MethodKey::Post, "/api/rag/upsert"), LOA::Operator);

        // Module execution
        routes.insert((MethodKey::Post, "/api/module/"), LOA::Operator); // prefix for all modules

        // Trust check/status
        routes.insert((MethodKey::Post, "/api/trust/check"), LOA::Guest);
        routes.insert((MethodKey::Get, "/api/trust/status"), LOA::Guest);

        Self { routes }
    }

    fn required_for(&self, method: MethodKey, path: &str) -> Option<LOA> {
        // Longest-prefix match
        self.routes
            .iter()
            .filter(|((m, pfx), _)| *m == method && path.starts_with(*pfx))
            .max_by_key(|((_, pfx), _)| pfx.len())
            .map(|(_, loa)| loa.clone())
    }
}

fn to_method_key(method: &AxumMethod) -> Option<MethodKey> {
    if method == AxumMethod::GET {
        Some(MethodKey::Get)
    } else if method == AxumMethod::POST {
        Some(MethodKey::Post)
    } else {
        None
    }
}

/// Enforce LOA according to the policy table; returns the user's LOA on success.
pub async fn enforce_request_loa(
    State(st): State<Arc<AppState>>,
    headers: &HeaderMap,
    method: &AxumMethod,
    path: &str,
    policy: &LoaPolicyTable,
) -> Result<LOA, AppError> {
    let method_key = to_method_key(method).ok_or_else(|| AppError::forbidden("method not allowed"))?;

    // Extract current user from license (or dev feature+env fallback)
    let user = extract_current_user(headers, &st.runtime_id, &st.canon_fingerprint)?;

    // Determine required LOA
    if let Some(required) = policy.required_for(method_key, path) {
        if user.loa >= required {
            Ok(user.loa)
        } else {
            Err(AppError::forbidden(format!(
                "Insufficient LOA: required {required:?}, got {:?}",
                user.loa
            )))
        }
    } else {
        // Default to Observer for unknown endpoints
        if user.loa >= LOA::Observer {
            Ok(user.loa)
        } else {
            Err(AppError::forbidden("Insufficient LOA for endpoint".to_string()))
        }
    }
}

/// Axum middleware that enforces LOA for incoming requests using the default policy table.
pub async fn loa_guard(
    State(st): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Response {
    let headers = req.headers().clone();
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let policy = LoaPolicyTable::mvp_defaults();

    match enforce_request_loa(State(st), &headers, &method, &path, &policy).await {
        Ok(_loa) => next.run(req).await,
        Err(e) => e.into_response(),
    }
}
