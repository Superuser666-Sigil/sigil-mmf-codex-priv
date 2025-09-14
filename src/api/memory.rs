use axum::{extract::State, Json, http::StatusCode};
use serde::{Deserialize, Serialize};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use std::sync::Arc;

use crate::{
    app_state::AppState, 
    security::{CurrentUser, extract_current_user_from_headers}, 
    loa::LOA, 
    api_errors::AppError,
    canonical_record::CanonicalRecord,
};

#[derive(Deserialize)]
pub struct MemoryWriteReq { 
    key: String, 
    text: String, 
    #[allow(dead_code)]
    session_id: String 
}

#[derive(Serialize)]
pub struct MemoryWriteResp { 
    success: bool, 
    id: String 
}

pub async fn memory_write(
    State(_st): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<MemoryWriteReq>,
) -> Result<(StatusCode, Json<MemoryWriteResp>), AppError> {
    let user: CurrentUser = extract_current_user_from_headers(&headers)?;
    if user.loa < LOA::Operator {
        return Err(AppError::forbidden("requires Operator"));
    }
    if req.key.trim().is_empty() || req.text.len() > 16 * 1024 {
        return Err(AppError::bad_request("invalid memory payload"));
    }

    let now = OffsetDateTime::now_utc().format(&Rfc3339).unwrap();
    let payload = serde_json::json!({
        "schema_version": 1,
        "key": format!("mem::{}::{}", user.user_id, req.key),
        "text": req.text,
        "ts": now,
        "user_id": user.user_id,
    });

    // Create properly signed CanonicalRecord
    let record_id = format!("mem_{}_{}", user.user_id, req.key);
    let rec = CanonicalRecord::new_signed(
        "memory_block",
        &record_id,
        &user.user_id,
        "user",
        payload,
        None,
    ).map_err(|e| AppError::internal(format!("Failed to create signed record: {e}")))?;

    // Persist to Canon Store
    let mut canon_store = _st.canon_store.lock().map_err(|e| AppError::internal(format!("canon store lock poisoned: {e}")))?;
    canon_store
        .add_record(rec.clone(), &user.loa, false)
        .map_err(|e| AppError::internal(format!("Failed to add record: {e}")))?;

    tracing::info!("Memory write: user={}, key={}, record_id={}", user.user_id, req.key, record_id);

    Ok((StatusCode::OK, Json(MemoryWriteResp { 
        success: true, 
        id: rec.id 
    })))
}

#[derive(Serialize)]
pub struct MemoryListItem { 
    id: String, 
    ts: String,
    key: String,
}

pub async fn memory_list(
    State(_st): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> Result<Json<Vec<MemoryListItem>>, AppError> {
    let user: CurrentUser = extract_current_user_from_headers(&headers)?;
    // Fetch memory records from canon store and filter by tenant (user)
    let recs: Vec<CanonicalRecord> = {
        let guard = _st
            .canon_store
            .lock()
            .map_err(|e| AppError::internal(format!("canon store lock poisoned: {e}")))?;
        guard.list_records(Some("memory_block"), &user.loa)
    };

    let items: Vec<MemoryListItem> = recs
        .into_iter()
        .filter(|r| r.tenant == user.user_id)
        .map(|r| MemoryListItem {
            id: r.id.clone(),
            ts: r.ts.to_rfc3339(),
            key: r
                .payload
                .get("key")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .split("::")
                .last()
                .unwrap_or("")
                .to_string(),
        })
        .collect();

    Ok(Json(items))
}

#[derive(Deserialize)]
pub struct RagUpsertReq {
    doc_id: String,
    title: String,
    text: String,
    #[allow(dead_code)]
    session_id: String,
}

#[derive(Serialize)]
pub struct RagUpsertResp {
    success: bool,
    doc_id: String,
}

pub async fn rag_upsert(
    State(_st): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<RagUpsertReq>,
) -> Result<(StatusCode, Json<RagUpsertResp>), AppError> {
    let user: CurrentUser = extract_current_user_from_headers(&headers)?;
    if user.loa < LOA::Operator {
        return Err(AppError::forbidden("requires Operator"));
    }
    if req.text.len() > 32 * 1024 {
        return Err(AppError::bad_request("document too large"));
    }

    let now = OffsetDateTime::now_utc().format(&Rfc3339).unwrap();
    let payload = serde_json::json!({
        "schema_version": 1,
        "doc_id": format!("rag::{}::{}", user.user_id, req.doc_id),
        "title": req.title,
        "text": req.text,
        "ts": now,
        "user_id": user.user_id,
        // "embedding": [], // optional vector embedding
    });

    // Create properly signed CanonicalRecord
    let record_id = format!("rag_{}_{}", user.user_id, req.doc_id);
    let rec = CanonicalRecord::new_signed(
        "rag_doc",
        &record_id,
        &user.user_id,
        "user",
        payload,
        None,
    ).map_err(|e| AppError::internal(format!("Failed to create signed record: {e}")))?;

    // Persist to Canon Store
    let mut canon_store = _st.canon_store.lock().map_err(|e| AppError::internal(format!("canon store lock poisoned: {e}")))?;
    canon_store
        .add_record(rec.clone(), &user.loa, false)
        .map_err(|e| AppError::internal(format!("Failed to add record: {e}")))?;

    tracing::info!("RAG upsert: user={}, doc_id={}, record_id={}", user.user_id, req.doc_id, record_id);

    Ok((StatusCode::OK, Json(RagUpsertResp {
        success: true,
        doc_id: req.doc_id,
    })))
}
