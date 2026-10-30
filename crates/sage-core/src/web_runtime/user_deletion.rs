//! Single-process admission for web-owned memory. Python rejects new auth after
//! local deletion; the process-local mark rejects requests authenticated earlier.
//! A restart discards those requests together with these marks.
use super::*;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::{OwnedRwLockReadGuard, OwnedRwLockWriteGuard, RwLock};

#[derive(Default)]
struct Owner {
    deleting: AtomicBool,
    activity: Arc<RwLock<()>>,
}

#[derive(Default)]
pub(super) struct OwnerActivity(Mutex<HashMap<(String, String), Arc<Owner>>>);

impl OwnerActivity {
    fn owner(&self, kind: &str, id: &str) -> AppResult<Arc<Owner>> {
        let mut owners = self
            .0
            .lock()
            .map_err(|_| AppError::internal("owner admission unavailable"))?;
        Ok(owners
            .entry((kind.to_owned(), id.to_owned()))
            .or_default()
            .clone())
    }

    pub(super) fn admit(&self, kind: &str, id: &str) -> AppResult<OwnedRwLockReadGuard<()>> {
        let owner = self.owner(kind, id)?;
        let guard = owner
            .activity
            .clone()
            .try_read_owned()
            .map_err(|_| busy())?;
        if owner.deleting.load(Ordering::SeqCst) {
            return Err(AppError::new(
                StatusCode::GONE,
                "User deletion is pending or completed",
            ));
        }
        Ok(guard)
    }

    pub(super) fn exclusive(
        &self,
        kind: &str,
        id: &str,
        deleting: bool,
    ) -> AppResult<OwnedRwLockWriteGuard<()>> {
        let owner = self.owner(kind, id)?;
        if deleting {
            owner.deleting.store(true, Ordering::SeqCst);
        }
        owner.activity.clone().try_write_owned().map_err(|_| busy())
    }
}

fn busy() -> AppError {
    AppError::new(
        StatusCode::CONFLICT,
        "busy; retry deletion after active work finishes",
    )
}

pub(super) async fn delete_user_runtime(
    State(state): State<WebAppState>,
    headers: HeaderMap,
    Path(user_id): Path<i64>,
) -> AppResult<Json<Value>> {
    ensure_internal_lifecycle_token(&state, &headers)?;
    if user_id <= 0 {
        return Err(AppError::new(StatusCode::BAD_REQUEST, "Invalid User ID"));
    }
    let owner_id = user_id.to_string();
    let _exclusive = state.owner_activity.exclusive("user", &owner_id, true)?;
    let mut conn = state
        .db
        .lock()
        .map_err(|_| AppError::internal("failed to acquire database lock"))?;
    let (conversations, identities) = purge_user(&mut conn, &owner_id)?;
    Ok(Json(json!({
        "user_id": user_id,
        "deletion": {"status": "succeeded", "retryable": false},
        "conversations_deleted": conversations,
        "identities_deleted": identities,
    })))
}

fn purge_user(conn: &mut PgConnection, owner_id: &str) -> AppResult<(usize, usize)> {
    conn.transaction::<_, AppError, _>(|conn| {
        // Bound blocked SQL. A lost response still leaves Python's intent pending.
        diesel::sql_query("SET LOCAL statement_timeout = '5s'").execute(conn)?;
        let sessions = web_sessions::table
            .filter(web_sessions::owner_type.eq("user"))
            .filter(web_sessions::owner_id.eq(owner_id))
            .select(WebSessionRow::as_select())
            .load(conn)?;
        for session in &sessions {
            delete_session_memory_for_agent(conn, session.agent_id)?;
        }
        let conversations = diesel::delete(
            web_sessions::table
                .filter(web_sessions::owner_type.eq("user"))
                .filter(web_sessions::owner_id.eq(owner_id)),
        )
        .execute(conn)?;
        let identities = diesel::delete(
            external_identities::table
                .filter(external_identities::identity_type.eq("user"))
                .filter(external_identities::external_id.eq(owner_id)),
        )
        .execute(conn)?;
        Ok((conversations, identities))
    })
}

#[cfg(test)]
mod tests;
