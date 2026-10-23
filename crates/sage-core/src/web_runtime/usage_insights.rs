//! Retained-message usage: a bounded read capability, never a transcript reader.
use super::{ChatRequest, InternalAgentClient, InternalAuthContext, ToolRegistry, WebAppState};
use crate::sage_agent::{NativeToolResult, Tool, ToolArgs};
use anyhow::{ensure, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use diesel::{
    prelude::*,
    sql_types::{Array, BigInt, Jsonb, Nullable, Text, Timestamptz},
};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    sync::{Arc, Mutex, TryLockError},
    time::{Duration, Instant},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Arguments {
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    #[serde(default = "utc")]
    timezone: String,
    #[serde(default = "day")]
    group_by: String,
    #[serde(default)]
    include_admin_tests: bool,
    #[serde(default = "page_limit")]
    limit: usize,
    #[serde(default)]
    cursor: Option<String>,
}

fn utc() -> String {
    "UTC".into()
}
fn day() -> String {
    "day".into()
}
fn page_limit() -> usize {
    1
}

impl Arguments {
    fn parse(value: &Value) -> Result<Self> {
        let args: Self =
            serde_json::from_value(value.clone()).context("invalid read_usage arguments")?;
        ensure!(args.start < args.end, "start must precede end");
        args.timezone
            .parse::<chrono_tz::Tz>()
            .context("timezone must be an IANA timezone")?;
        ensure!(
            ["total", "user", "day", "model"].contains(&args.group_by.as_str()),
            "group_by must be total, user, day, or model"
        );
        ensure!(
            args.group_by != "total" || args.cursor.is_none(),
            "total returns one scope aggregate and does not accept a cursor"
        );
        ensure!(
            (1..=10).contains(&args.limit),
            "limit must be between 1 and 10; byte budget may return fewer rows"
        );
        Ok(args)
    }

    fn scope(&self) -> String {
        let digest = Sha256::digest(
            json!([
                self.start,
                self.end,
                self.timezone,
                self.group_by,
                self.include_admin_tests
            ])
            .to_string(),
        );
        URL_SAFE_NO_PAD.encode(&digest[..16])
    }

    fn after(&self) -> Result<Option<(String, i64)>> {
        self.cursor
            .as_ref()
            .map(|cursor| {
                ensure!(cursor.len() <= 600, "invalid cursor");
                let (scope, key) = cursor.split_once('.').context("invalid cursor")?;
                ensure!(
                    scope == self.scope(),
                    "cursor requires identical range, timezone, grouping, and filters"
                );
                let position: (String, i64) =
                    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(key).context("invalid cursor")?)
                        .context("invalid cursor")?;
                ensure!(
                    !position.0.is_empty() && position.0.len() <= 256 && position.1 >= 0,
                    "invalid cursor"
                );
                if self.group_by == "user" {
                    let id = position.0.parse::<i32>().context("invalid cursor")?;
                    ensure!(id > 0 && id.to_string() == position.0, "invalid cursor");
                }
                Ok(position)
            })
            .transpose()
    }

    fn cursor_for(&self, key: &str, count: i64) -> String {
        format!(
            "{}.{}",
            self.scope(),
            URL_SAFE_NO_PAD.encode(json!([key, count]).to_string())
        )
    }
}

#[derive(QueryableByName)]
struct JsonRow {
    #[diesel(sql_type = Jsonb)]
    row: Value,
}

// Aggregate messages and observations independently: expanding trace arrays must
// never multiply retained-message counts. Tokens are observations, not billing.
const USAGE_SQL: &str = r#"
WITH base AS MATERIALIZED (
 SELECT m.id, m.role, m.tool_results, s.owner_id, s.id AS session_id,
 CASE $5 WHEN 'total' THEN 'total' WHEN 'user' THEN s.owner_id WHEN 'day' THEN to_char(m.created_at AT TIME ZONE $3, 'YYYY-MM-DD')
 ELSE CASE WHEN m.role='assistant' AND m.tool_results->>'model_source'='request'
 AND jsonb_typeof(m.tool_results->'model')='string' AND m.tool_results->>'model'<>''
 THEN 'request:' || (m.tool_results->>'model') ELSE 'unknown' END END AS key
 FROM messages m JOIN web_sessions s ON s.agent_id=m.agent_id
 WHERE s.owner_type='user' AND s.owner_id=ANY($4) AND m.user_id='user:' || s.owner_id
 AND m.role IN ('user','assistant') AND m.created_at >= $1 AND m.created_at < $2
), raw AS (
 SELECT b.id, d->'metadata' AS meta
 FROM (SELECT DISTINCT id,role,tool_results FROM base) b CROSS JOIN LATERAL jsonb_array_elements(
 CASE WHEN jsonb_typeof(b.tool_results#>'{conversation_trace,trace_deltas}')='array'
 THEN b.tool_results#>'{conversation_trace,trace_deltas}' ELSE '[]'::jsonb END) d
 WHERE b.role='assistant' AND d->>'kind'='timing' AND d->>'title'='Model usage'
), parsed AS (
 SELECT id, CASE WHEN meta->>'model_source'='request' AND jsonb_typeof(meta->'model')='string'
 AND meta->>'model'<>'' THEN 'request:' || (meta->>'model') ELSE 'unknown' END AS model,
 CASE WHEN meta->>'step' ~ '^[0-9]{1,9}$' THEN (meta->>'step')::bigint END AS step,
 CASE WHEN meta->>'attempt' ~ '^[0-9]{1,9}$' THEN (meta->>'attempt')::bigint END AS attempt,
 CASE WHEN jsonb_typeof(meta->'prompt_tokens')='number' AND meta->>'prompt_tokens' ~ '^[0-9]{1,18}$'
 THEN (meta->>'prompt_tokens')::numeric END AS p,
 CASE WHEN jsonb_typeof(meta->'completion_tokens')='number' AND meta->>'completion_tokens' ~ '^[0-9]{1,18}$'
 THEN (meta->>'completion_tokens')::numeric END AS c,
 CASE WHEN jsonb_typeof(meta->'total_tokens')='number' AND meta->>'total_tokens' ~ '^[0-9]{1,18}$'
 THEN (meta->>'total_tokens')::numeric END AS t
 FROM raw
), observations AS MATERIALIZED (
 SELECT id, step, attempt, count(*)-1 AS duplicates,
 count(DISTINCT jsonb_build_array(p,c,t,model))>1 AS conflict,
 CASE WHEN count(DISTINCT model)=1 THEN min(model) ELSE 'unknown' END AS model,
 CASE WHEN count(DISTINCT jsonb_build_array(p,c,t,model))=1 THEN min(p) END AS p,
 CASE WHEN count(DISTINCT jsonb_build_array(p,c,t,model))=1 THEN min(c) END AS c,
 CASE WHEN count(DISTINCT jsonb_build_array(p,c,t,model))=1 THEN min(t) END AS t
 FROM parsed WHERE step IS NOT NULL AND attempt IS NOT NULL GROUP BY id,step,attempt
), message_groups AS (
 SELECT key, count(DISTINCT id) FILTER (WHERE role='user') AS human_messages,
 count(DISTINCT id) FILTER (WHERE role='assistant') AS assistant_messages,
 count(DISTINCT owner_id) AS active_users, count(DISTINCT session_id) AS active_conversations,
 count(DISTINCT id) FILTER (WHERE role='assistant' AND EXISTS (
 SELECT 1 FROM observations o WHERE o.id=base.id AND (p IS NOT NULL OR c IS NOT NULL OR t IS NOT NULL))) AS assistant_with_usage
 FROM base GROUP BY key
), usage_groups AS (
 SELECT CASE WHEN $5='model' THEN o.model ELSE b.key END AS key,
 count(*) AS observations, count(DISTINCT o.id) AS observation_records,
 sum(duplicates) AS duplicates, count(*) FILTER (WHERE conflict) AS conflicts,
 jsonb_build_array(sum(p),sum(c),sum(t)) AS tokens,
 jsonb_build_array(count(p),count(c),count(t)) AS token_coverage
 FROM observations o JOIN (SELECT DISTINCT id,key FROM base) b ON b.id=o.id GROUP BY 1
), invalid_groups AS (
 SELECT CASE WHEN $5='model' THEN p.model ELSE b.key END AS key, count(*) AS invalid_observations
 FROM parsed p JOIN (SELECT DISTINCT id,key FROM base) b ON b.id=p.id
 WHERE p.step IS NULL OR p.attempt IS NULL GROUP BY 1
), keys AS (
 SELECT key FROM message_groups UNION SELECT key FROM usage_groups UNION SELECT key FROM invalid_groups
 UNION SELECT 'total' WHERE $5='total'
)
SELECT jsonb_build_object('key',k.key,'human_messages',coalesce(m.human_messages,0),
 'total_messages',coalesce(m.human_messages,0)+coalesce(m.assistant_messages,0),
 'assistant_messages',coalesce(m.assistant_messages,0),'active_users',coalesce(m.active_users,0),
 'active_conversations',coalesce(m.active_conversations,0),'assistant_with_usage',coalesce(m.assistant_with_usage,0),
 'observations',coalesce(u.observations,0),'observation_records',coalesce(u.observation_records,0),
 'duplicates',coalesce(u.duplicates,0),'conflicts',coalesce(u.conflicts,0),
 'invalid_observations',coalesce(i.invalid_observations,0),
 'tokens',coalesce(u.tokens,'[null,null,null]'::jsonb),
 'token_coverage',coalesce(u.token_coverage,'[0,0,0]'::jsonb)) AS row
FROM keys k LEFT JOIN message_groups m ON m.key=k.key LEFT JOIN usage_groups u ON k.key=u.key
LEFT JOIN invalid_groups i ON i.key=k.key
WHERE $6::text IS NULL OR CASE WHEN $5='user' THEN
 (coalesce(m.human_messages,0)+coalesce(m.assistant_messages,0)<$8 OR
  (coalesce(m.human_messages,0)+coalesce(m.assistant_messages,0)=$8 AND k.key::bigint>$9))
 ELSE k.key COLLATE "C">$6 COLLATE "C" END
ORDER BY CASE WHEN $5='user' THEN coalesce(m.human_messages,0)+coalesce(m.assistant_messages,0) END DESC,
 CASE WHEN $5='user' THEN k.key::bigint END, k.key COLLATE "C" LIMIT $7
"#;

pub(super) fn register(
    registry: &mut ToolRegistry,
    state: &WebAppState,
    request: &ChatRequest,
    auth: &InternalAuthContext,
) {
    let tool = UsageTool {
        db: state.db.clone(),
        internal: state.internal.clone(),
        auth: auth.clone(),
        database_enabled: request.tools.iter().any(|t| t == "db-query"),
    };
    if tool.authorized() {
        registry.register(Arc::new(tool));
    }
}

struct UsageTool {
    db: Arc<Mutex<PgConnection>>,
    internal: InternalAgentClient,
    auth: InternalAuthContext,
    database_enabled: bool,
}

#[async_trait::async_trait]
impl Tool for UsageTool {
    fn name(&self) -> &str {
        "read_usage"
    }
    fn description(&self) -> &str {
        "Read exact retained Sage message counts for existing Users across the total scope or by user, local day, or model. For scope-wide totals, call group_by=total with the same interval/timezone/test filters and quote its total_messages, human_messages, assistant_messages and observed tokens directly; do not sum grouped pages. Total covers all eligible Users in the scope, returns one row even when empty, and has no cursor. Every aggregate row includes total_messages (human plus assistant). Empty scopes have zero message counts and null token sums. User groups rank by total human+assistant messages descending, ties by numeric User ID ascending: first pages answer top-user questions. Day/model groups sort by key ascending. Supply explicit offset timestamps for [start,end); timezone defaults UTC. Admin tests excluded unless explicitly included. Deleted Sage sessions and deleted Users excluded; encrypted review-log retention is separate. Continue next_cursor with identical filters; pages are live, not a cross-store snapshot. Model keys request:* name requested models, never provider-confirmed; human/historical missing models are unknown. Tokens and token_coverage arrays follow token_fields (prompt,completion,total): sums of known values and number of observations containing each field, null when none. Observations deduplicate per assistant record/step/attempt; retries are distinct requests. observation_records counts records with keyed observations; assistant_with_usage counts records with any valid token value. Always report assistant-message token coverage as assistant_with_usage of assistant_messages (for example 13 of 25 assistant messages); token_coverage is per-field observation counts, not the message-coverage denominator. For zero assistant messages, message coverage is not applicable. Conflicts discard ambiguous tokens; invalid_observations lack attempt identity. Model token groups use observation models separately from message models; active counts and records overlap across groups. No cost without versioned prices. Whole rows fit 1200 UTF-8 bytes."
    }
    fn native_parameters(&self) -> Result<Value> {
        Ok(json!({"type":"object","properties":{
            "start":{"type":"string","description":"Inclusive RFC3339 timestamp with explicit UTC offset."},
            "end":{"type":"string","description":"Exclusive RFC3339 timestamp with explicit UTC offset."},
            "timezone":{"type":"string","description":"IANA timezone for local-day buckets; default UTC."},
            "group_by":{"type":"string","enum":["total","user","day","model"],"description":"Use total for exact scope-wide counts and tokens in one row, including an empty scope; do not sum grouped pages for scope totals. Default day. User: total_messages descending, numeric User ID ascending on ties. Day/model: key ascending."},
            "include_admin_tests":{"type":"boolean","description":"Explicitly include provisioned Admin test Users; default false."},
            "limit":{"type":"integer","minimum":1,"maximum":10,"description":"Maximum groups; default 1. Byte budget may return fewer."},
            "cursor":{"type":"string","description":"next_cursor from prior grouped page; retain all filters. Omit for total."}
        },"required":["start","end"],"additionalProperties":false}))
    }
    async fn execute_native(&self, args: &ToolArgs) -> Result<NativeToolResult> {
        if !self.authorized() {
            return Ok(NativeToolResult::failure(
                "forbidden",
                "read_usage requires an approved Admin with Database enabled.",
            ));
        }
        let value = Value::Object(args.iter().map(|(k, v)| (k.clone(), v.clone())).collect());
        if let Err(error) = Arguments::parse(&value).and_then(|a| a.after()) {
            return Ok(NativeToolResult::failure(
                "invalid_arguments",
                error.to_string(),
            ));
        }
        match self.read(value).await {
            Ok(result) => Ok(NativeToolResult::success(result)),
            Err(error) => {
                tracing::warn!(error = %error, "read_usage failed");
                Ok(NativeToolResult::failure("usage_unavailable", "Usage unavailable: could not validate current Users or complete a bounded retained-data query. Narrow the range or retry; no counts were inferred."))
            }
        }
    }
}

#[derive(QueryableByName)]
struct OwnerRow {
    #[diesel(sql_type = Text)]
    owner_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UsersResponse {
    users: Vec<User>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct User {
    id: i32,
    is_test: bool,
}

impl UsageTool {
    fn authorized(&self) -> bool {
        self.auth.kind == "admin" && self.auth.approved && self.database_enabled
    }

    async fn read(&self, value: Value) -> Result<Value> {
        let args = Arguments::parse(&value)?;
        let start = args.start;
        let end = args.end;
        let owners: Vec<i32> = with_connection(self.db.clone(), move |conn| {
            with_query_timeout(conn, |conn| {
                let rows = diesel::sql_query(
                    "SELECT DISTINCT s.owner_id FROM web_sessions s
                JOIN messages m ON m.agent_id=s.agent_id WHERE s.owner_type='user'
                AND m.user_id='user:' || s.owner_id AND m.role IN ('user','assistant')
                AND m.created_at >= $1 AND m.created_at < $2 ORDER BY s.owner_id LIMIT 10001",
                )
                .bind::<Timestamptz, _>(start)
                .bind::<Timestamptz, _>(end)
                .load::<OwnerRow>(conn)?;
                ensure!(
                    rows.len() <= 10000,
                    "more than 10000 candidate owners; narrow range"
                );
                Ok(rows
                    .into_iter()
                    .filter_map(|r| {
                        r.owner_id
                            .parse::<i32>()
                            .ok()
                            .filter(|id| *id > 0 && id.to_string() == r.owner_id)
                    })
                    .collect())
            })
        })
        .await?;
        let mut eligible = Vec::new();
        // Empty selections still perform the live Admin check.
        let batches = if owners.is_empty() {
            vec![owners.as_slice()]
        } else {
            owners.chunks(200).collect()
        };
        for batch in batches {
            let mut response = self
                .internal
                .http
                .post(format!(
                    "{}/internal/agent/admin/usage-users",
                    self.internal.backend_url
                ))
                .header(
                    "X-Internal-Agent-Token",
                    &self.internal.internal_agent_token,
                )
                .timeout(Duration::from_secs(10))
                .json(&json!({"actor":self.auth,"user_ids":batch}))
                .send()
                .await?
                .error_for_status()?;
            let mut bytes = Vec::new();
            while let Some(chunk) = response.chunk().await? {
                ensure!(
                    bytes.len() + chunk.len() <= 32768,
                    "oversized user provenance response"
                );
                bytes.extend_from_slice(&chunk);
            }
            let response: UsersResponse = serde_json::from_slice(&bytes)?;
            let mut seen = HashSet::new();
            for user in response.users {
                ensure!(
                    batch.contains(&user.id) && seen.insert(user.id),
                    "foreign or duplicate provenance user"
                );
                if !user.is_test || args.include_admin_tests {
                    eligible.push(user.id.to_string());
                }
            }
        }
        with_connection(self.db.clone(), move |conn| {
            query_usage(conn, &value, &eligible)
        })
        .await
    }
}

/// Bound queueing too: a dropped Tool future must not leave a worker waiting
/// indefinitely for the application's shared session connection.
async fn with_connection<T, F>(db: Arc<Mutex<PgConnection>>, operation: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce(&mut PgConnection) -> Result<T> + Send + 'static,
{
    let deadline = Instant::now() + Duration::from_secs(1);
    tokio::task::spawn_blocking(move || {
        let mut conn = loop {
            ensure!(Instant::now() < deadline, "usage database busy; retry");
            match db.try_lock() {
                Ok(conn) => break conn,
                Err(TryLockError::Poisoned(_)) => anyhow::bail!("usage database lock unavailable"),
                Err(TryLockError::WouldBlock) => std::thread::sleep(Duration::from_millis(10)),
            }
        };
        operation(&mut conn)
    })
    .await?
}

#[derive(QueryableByName)]
struct TimeoutSetting {
    #[diesel(sql_type = BigInt)]
    millis: i64,
}

/// Savepoints contain a canceled statement's failed-transaction state. Restore
/// the caller's setting on success; rollback restores it on failure. Existing
/// shorter timeouts are preserved, including inside the isolated test fixtures.
fn with_query_timeout<T>(
    conn: &mut PgConnection,
    operation: impl FnOnce(&mut PgConnection) -> Result<T>,
) -> Result<T> {
    conn.transaction(|conn| {
        let prior = diesel::sql_query(
            "SELECT setting::bigint AS millis FROM pg_settings WHERE name='statement_timeout'",
        )
        .get_result::<TimeoutSetting>(conn)?
        .millis;
        let timeout = if prior == 0 { 5000 } else { prior.min(5000) };
        let set_timeout = |conn: &mut PgConnection, millis: i64| -> Result<()> {
            diesel::sql_query("SELECT set_config('statement_timeout',$1,true)")
                .bind::<Text, _>(millis.to_string())
                .execute(conn)?;
            Ok(())
        };
        set_timeout(conn, timeout)?;
        let result = operation(conn)?;
        set_timeout(conn, prior)?;
        Ok(result)
    })
}

/// `eligible_users` must come from the authenticated control-plane classifier.
pub(super) fn query_usage(
    conn: &mut PgConnection,
    arguments: &Value,
    eligible_users: &[String],
) -> Result<Value> {
    with_query_timeout(conn, |conn| {
        query_usage_with_connection(conn, arguments, eligible_users)
    })
}

fn query_usage_with_connection(
    conn: &mut PgConnection,
    arguments: &Value,
    eligible_users: &[String],
) -> Result<Value> {
    let args = Arguments::parse(arguments)?;
    let after = args.after()?;
    let rows = diesel::sql_query(USAGE_SQL)
        .bind::<Timestamptz, _>(args.start)
        .bind::<Timestamptz, _>(args.end)
        .bind::<Text, _>(&args.timezone)
        .bind::<Array<Text>, _>(eligible_users)
        .bind::<Text, _>(&args.group_by)
        .bind::<Nullable<Text>, _>(after.as_ref().map(|(key, _)| key.as_str()))
        .bind::<BigInt, _>((args.limit + 1) as i64)
        .bind::<BigInt, _>(after.as_ref().map(|(_, count)| *count).unwrap_or(0))
        .bind::<BigInt, _>(if args.group_by == "user" {
            after
                .as_ref()
                .map(|(key, _)| key.parse::<i64>())
                .transpose()?
                .unwrap_or(0)
        } else {
            0
        })
        .load::<JsonRow>(conn)?
        .into_iter()
        .map(|r| r.row)
        .collect::<Vec<_>>();
    let mut result = json!({
        "source":"retained_sage_messages/current_users",
        "start":args.start,"end":args.end,"interval":"[start,end)","timezone":args.timezone,
        "group_by":args.group_by,"include_admin_tests":args.include_admin_tests,
        "order":match args.group_by.as_str() {"user"=>"messages_desc,user_id_asc","total"=>"single_scope",_=>"key_asc"},
        "coverage":"live; messages exact; assistant coverage=assistant_with_usage/assistant_messages; token_coverage=per-field observations",
        "token_fields":["prompt","completion","total"],
        "cost":"unavailable:no_versioned_prices","rows":[],"next_cursor":null
    });
    for (index, row) in rows.iter().take(args.limit).enumerate() {
        let key = row["key"].as_str().context("invalid usage group")?;
        let prior = result.clone();
        result["rows"].as_array_mut().unwrap().push(row.clone());
        let count = row["total_messages"]
            .as_i64()
            .context("invalid total message count")?;
        result["next_cursor"] = if index + 1 < rows.len() {
            json!(args.cursor_for(key, count))
        } else {
            Value::Null
        };
        if serde_json::to_vec(&result)?.len() > 1200 {
            ensure!(
                index > 0,
                "usage group cannot fit the 1200-byte page budget"
            );
            result = prior;
            break;
        }
    }
    Ok(result)
}

#[cfg(test)]
#[path = "usage_insights_tests.rs"]
mod tests;
