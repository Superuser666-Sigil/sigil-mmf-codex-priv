use axum::{Json, extract::State, http::StatusCode};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::{
    api_errors::AppError, 
    app_state::AppState, 
    security::{CurrentUser, extract_current_user_from_headers}, 
    loa::LOA,
};

#[derive(Deserialize)]
pub struct CommitRequest { 
    proposal_id: String 
}

#[derive(Serialize)]
pub struct CommitResponse { 
    committed: bool, 
    record_id: String 
}

pub async fn commit_system_proposal(
    State(st): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<CommitRequest>,
) -> Result<(StatusCode, Json<CommitResponse>), AppError> {
    let user: CurrentUser = extract_current_user_from_headers(&headers)?;
    if user.loa != LOA::Root {
        return Err(AppError::forbidden("only root can commit proposals"));
    }

    // Commit the proposal (includes quorum check and removal)
    let committed_proposal = {
        let mut qs = st.quorum.write().await;
        qs.commit_proposal(&req.proposal_id)
            .map_err(|e| AppError::from(e))?
    };

    // Rebuild and verify the canonical record that will be stored
    let record = st.rebuild_canonical_record_from_proposal(&committed_proposal)
        .map_err(|_| AppError::internal("proposal invalid"))?;

    // Enforce that the record is in system space
    if record.space != "system" {
        return Err(AppError::bad_request("proposal is not system space"));
    }

    // Verify Root signature and witness signatures again against WitnessRegistry
    st.verify_record_signatures(&record)
        .map_err(|_| AppError::forbidden("signature verification failed"))?;

    // TODO: Commit to Canon store as Root
    // st.canon_store.add_record(record.clone(), &LOA::Root, false)
    //     .map_err(|_| AppError::internal("canon write failed"))?;
    tracing::info!("System proposal committed: {}", committed_proposal.id);

    Ok((StatusCode::OK, Json(CommitResponse { 
        committed: true, 
        record_id: record.id 
    })))
}
