//! Sage-owned Agent Settings writes for the Admin Config Tool Set.
//!
//! Agent Settings live in Sage's store, which is what Conversations read.
//! `update_agent_settings` and the Agent Settings part of `configure_instance`
//! therefore validate and write here, then record the change in the control
//! plane's Audit Log. A change that cannot be recorded is rolled back, so an
//! Admin Conversation never changes Agent Settings without audit provenance.

use super::*;

const RECORD_ENDPOINT: &str = "record-agent-settings-change";
const MAX_GUIDED_RULES: usize = 8;
const AUDIT_UNAVAILABLE: &str =
    "Agent Settings were not changed because the change could not be recorded in the Audit Log. Try again.";
const ROLLBACK_INCOMPLETE: &str =
    "Agent Settings may still include this change: it could not be recorded in the Audit Log, and rolling it back did not complete. Read the Agent Settings before retrying.";

/// One requested change within a single scope (global or one User Type).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum AgentSettingWrite {
    Set {
        key: String,
        value: String,
    },
    /// Remove a User Type override so the global value applies again.
    Revert {
        key: String,
    },
}

impl AgentSettingWrite {
    fn key(&self) -> &str {
        match self {
            Self::Set { key, .. } | Self::Revert { key } => key,
        }
    }
}

/// A value that actually changed. `None` means no User Type override.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct AgentSettingChange {
    key: String,
    old_value: Option<String>,
    new_value: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct AgentSettingsUpdate {
    user_type_id: Option<i32>,
    writes: Vec<AgentSettingWrite>,
}

/// Parses `update_agent_settings` arguments into one validated scope.
pub(super) fn parse_update_agent_settings(
    args: &ToolArgs,
) -> std::result::Result<AgentSettingsUpdate, String> {
    let updates = match args.get("updates") {
        None | Some(Value::Null) => serde_json::Map::new(),
        Some(Value::Object(updates)) => updates.clone(),
        Some(_) => return Err("updates must be an object of setting keys and values".to_string()),
    };
    let revert_keys = match args.get("revert_keys") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(keys)) => keys
            .iter()
            .map(|key| {
                key.as_str()
                    .map(str::trim)
                    .filter(|key| !key.is_empty())
                    .map(str::to_string)
                    .ok_or_else(|| "revert_keys must be an array of setting keys".to_string())
            })
            .collect::<std::result::Result<Vec<_>, _>>()?,
        Some(_) => return Err("revert_keys must be an array of setting keys".to_string()),
    };
    let user_type_id = match optional_i64_arg(args, "user_type_id").map_err(|e| e.to_string())? {
        None => None,
        Some(id) => Some(
            i32::try_from(id)
                .ok()
                .filter(|id| *id >= 1)
                .ok_or_else(|| "user_type_id must be a positive integer".to_string())?,
        ),
    };

    let mut writes = Vec::new();
    for (key, value) in updates {
        let key = key.trim().to_string();
        if key.is_empty() {
            return Err("Agent Setting keys must not be blank".to_string());
        }
        let value = match value {
            Value::String(value) => value,
            Value::Number(value) => value.to_string(),
            Value::Bool(value) => value.to_string(),
            _ => return Err(format!("The value for {} must be a string", key)),
        };
        writes.push(AgentSettingWrite::Set { key, value });
    }
    writes.sort_by(|left, right| left.key().cmp(right.key()));

    if writes.is_empty() && revert_keys.is_empty() {
        return Err("At least one Agent Setting operation is required".to_string());
    }
    if user_type_id.is_none() && !revert_keys.is_empty() {
        return Err("Only User Type overrides can be reverted".to_string());
    }
    let mut reverted = Vec::new();
    for key in revert_keys {
        if writes.iter().any(|write| write.key() == key) {
            return Err(format!(
                "{} cannot be updated and reverted in the same call",
                key
            ));
        }
        if !reverted.contains(&key) {
            reverted.push(key);
        }
    }
    reverted.sort();
    writes.extend(
        reverted
            .into_iter()
            .map(|key| AgentSettingWrite::Revert { key }),
    );
    Ok(AgentSettingsUpdate {
        user_type_id,
        writes,
    })
}

/// Removes guided-setup rules from the control-plane payload and turns them
/// into global Agent Settings writes. An empty list leaves that setting as it
/// is, so re-running setup never silently clears an operator's rules.
/// Product-required rules are kept, as Sage restores them at startup anyway.
pub(super) fn take_guided_agent_settings(
    payload: &mut Value,
) -> std::result::Result<(Vec<AgentSettingWrite>, serde_json::Map<String, Value>), String> {
    let object = payload
        .as_object_mut()
        .ok_or_else(|| "configure_instance arguments must be an object".to_string())?;
    let rules = guided_rule_list(object.remove("behavior_rules"), "behavior_rules")?;
    let forbidden = guided_rule_list(object.remove("forbidden_topics"), "forbidden_topics")?;
    let mut writes = Vec::new();
    let mut saved = serde_json::Map::new();
    if !forbidden.is_empty() {
        writes.push(AgentSettingWrite::Set {
            key: "prompt_forbidden".to_string(),
            value: serde_json::to_string(&forbidden).expect("topics serialize"),
        });
        saved.insert("forbidden_topics".to_string(), Value::from(forbidden));
    }
    if !rules.is_empty() {
        let operator_rules = serde_json::to_string(&rules).expect("rules serialize");
        let required_rules = serde_json::to_string(&DEFAULT_PROMPT_RULES).expect("rules serialize");
        writes.push(AgentSettingWrite::Set {
            key: "prompt_rules".to_string(),
            value: merge_prompt_rules(&operator_rules, &required_rules).unwrap_or(operator_rules),
        });
        saved.insert("behavior_rules".to_string(), Value::from(rules));
    }
    Ok((writes, saved))
}

fn guided_rule_list(value: Option<Value>, label: &str) -> std::result::Result<Vec<String>, String> {
    let items = match value {
        None | Some(Value::Null) => return Ok(Vec::new()),
        Some(Value::Array(items)) => items,
        Some(_) => return Err(format!("{} must be an array of strings", label)),
    };
    if items.len() > MAX_GUIDED_RULES {
        return Err(format!(
            "{} accepts at most {} items",
            label, MAX_GUIDED_RULES
        ));
    }
    items
        .into_iter()
        .map(|item| match item {
            Value::String(text) if !text.trim().is_empty() => Ok(text.trim().to_string()),
            Value::String(_) => Err(format!("{} cannot contain blank values", label)),
            _ => Err(format!("{} must be an array of strings", label)),
        })
        .collect()
}

/// Checks every key exists and every value is valid before anything changes.
fn validate_agent_setting_writes(
    state: &WebAppState,
    writes: &[AgentSettingWrite],
) -> std::result::Result<(), String> {
    for write in writes {
        let row = load_ai_config_row(state, write.key()).map_err(|error| {
            if error.status == StatusCode::NOT_FOUND {
                format!("Unknown Agent Setting: {}", write.key())
            } else {
                error.message
            }
        })?;
        if let AgentSettingWrite::Set { key, value } = write {
            validate_ai_config_value(key, &row.value_type, &row.category, value)
                .map_err(|error| error.message)?;
        }
    }
    Ok(())
}

fn current_value(
    conn: &mut diesel::PgConnection,
    user_type_id: Option<i32>,
    key: &str,
) -> diesel::QueryResult<Option<String>> {
    match user_type_id {
        None => ai_config::table
            .filter(ai_config::key.eq(key))
            .select(ai_config::value)
            .first::<String>(conn)
            .optional(),
        Some(user_type_id) => ai_config_user_type_overrides::table
            .filter(ai_config_user_type_overrides::ai_config_key.eq(key))
            .filter(ai_config_user_type_overrides::user_type_id.eq(user_type_id))
            .select(ai_config_user_type_overrides::value)
            .first::<String>(conn)
            .optional(),
    }
}

fn store_value(
    conn: &mut diesel::PgConnection,
    user_type_id: Option<i32>,
    key: &str,
    value: Option<&str>,
) -> diesel::QueryResult<()> {
    match (user_type_id, value) {
        (None, Some(value)) => {
            diesel::update(ai_config::table.filter(ai_config::key.eq(key)))
                .set((
                    ai_config::value.eq(value),
                    ai_config::updated_at.eq(chrono::Utc::now()),
                ))
                .execute(conn)?;
        }
        // Global settings always have a value; parsing rejects global reverts.
        (None, None) => {}
        (Some(user_type_id), Some(value)) => {
            diesel::sql_query(
                "INSERT INTO ai_config_user_type_overrides (id, ai_config_key, user_type_id, value, updated_at) \
                 VALUES ($1, $2, $3, $4, NOW()) \
                 ON CONFLICT (ai_config_key, user_type_id) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()",
            )
            .bind::<SqlUuid, _>(Uuid::new_v4())
            .bind::<Varchar, _>(key)
            .bind::<Integer, _>(user_type_id)
            .bind::<Text, _>(value)
            .execute(conn)?;
        }
        (Some(user_type_id), None) => {
            diesel::delete(
                ai_config_user_type_overrides::table
                    .filter(ai_config_user_type_overrides::ai_config_key.eq(key))
                    .filter(ai_config_user_type_overrides::user_type_id.eq(user_type_id)),
            )
            .execute(conn)?;
        }
    }
    Ok(())
}

/// Applies every write in one transaction and returns what actually changed.
fn apply_agent_setting_writes(
    state: &WebAppState,
    user_type_id: Option<i32>,
    writes: &[AgentSettingWrite],
) -> AppResult<Vec<AgentSettingChange>> {
    let mut conn = state
        .db
        .lock()
        .map_err(|_| AppError::internal("failed to acquire database lock"))?;
    conn.transaction::<_, diesel::result::Error, _>(|conn| {
        let mut changes = Vec::new();
        for write in writes {
            let old_value = current_value(conn, user_type_id, write.key())?;
            let new_value = match write {
                AgentSettingWrite::Set { value, .. } => Some(value.clone()),
                AgentSettingWrite::Revert { .. } => None,
            };
            if old_value == new_value {
                continue;
            }
            store_value(conn, user_type_id, write.key(), new_value.as_deref())?;
            changes.push(AgentSettingChange {
                key: write.key().to_string(),
                old_value,
                new_value,
            });
        }
        Ok(changes)
    })
    .map_err(internal_error)
}

/// How rolling back an applied change went.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Rollback {
    Restored,
    /// Some values changed again after this write (for example from the
    /// Admin AI Config page) and were left as they are.
    Superseded,
    Failed,
}

/// Puts back the values a change replaced, but only where the value is still
/// the one this change wrote, so a newer edit is never overwritten.
fn restore_agent_setting_changes(
    state: &WebAppState,
    user_type_id: Option<i32>,
    changes: &[AgentSettingChange],
) -> Rollback {
    let Ok(mut conn) = state.db.lock() else {
        return Rollback::Failed;
    };
    let restored = conn.transaction::<_, diesel::result::Error, _>(|conn| {
        let mut superseded = false;
        for change in changes.iter().rev() {
            if current_value(conn, user_type_id, &change.key)? != change.new_value {
                superseded = true;
                continue;
            }
            store_value(conn, user_type_id, &change.key, change.old_value.as_deref())?;
        }
        Ok(superseded)
    });
    match restored {
        Ok(false) => Rollback::Restored,
        Ok(true) => Rollback::Superseded,
        Err(error) => {
            warn!("Agent Settings rollback failed: {}", error);
            Rollback::Failed
        }
    }
}

/// The values a Conversation now sees for `keys` in this scope.
fn saved_values(
    state: &WebAppState,
    user_type_id: Option<i32>,
    keys: &[String],
) -> AppResult<serde_json::Map<String, Value>> {
    let values = match user_type_id {
        None => load_all_ai_config_rows(state)?
            .into_iter()
            .map(|row| (row.key, row.value))
            .collect::<HashMap<_, _>>(),
        Some(user_type_id) => load_effective_ai_config_rows(state, user_type_id)?
            .into_iter()
            .map(|row| (row.key, row.value))
            .collect::<HashMap<_, _>>(),
    };
    Ok(keys
        .iter()
        .filter_map(|key| {
            values
                .get(key)
                .map(|value| (key.clone(), Value::from(value.clone())))
        })
        .collect())
}

/// Records Agent Settings changes in the control-plane Audit Log.
pub(super) async fn record_agent_settings_change(
    internal: &InternalAgentClient,
    auth: &InternalAuthContext,
    conversation_id: &str,
    tool_name: &str,
    user_type_id: Option<i32>,
    changes: &[AgentSettingChange],
) -> std::result::Result<(), AdminConfigToolError> {
    let changes = changes
        .iter()
        .map(|change| {
            json!({
                "key": change.key,
                "old_value": change.old_value,
                "new_value": change.new_value,
            })
        })
        .collect::<Vec<_>>();
    internal
        .admin_config_direct_tool(
            RECORD_ENDPOINT,
            auth,
            conversation_id,
            json!({
                "tool_name": tool_name,
                "user_type_id": user_type_id,
                "changes": changes,
            }),
        )
        .await
        .map(|_| ())
}

/// Applies writes, records them, and rolls them back if recording fails.
async fn apply_and_record(
    state: &WebAppState,
    internal: &InternalAgentClient,
    auth: &InternalAuthContext,
    conversation_id: &str,
    tool_name: &str,
    user_type_id: Option<i32>,
    writes: &[AgentSettingWrite],
) -> std::result::Result<Vec<AgentSettingChange>, NativeToolResult> {
    let changes = apply_agent_setting_writes(state, user_type_id, writes)
        .map_err(|error| NativeToolResult::failure("execution_failed", error.message))?;
    match record_agent_settings_change(
        internal,
        auth,
        conversation_id,
        tool_name,
        user_type_id,
        &changes,
    )
    .await
    {
        Ok(()) => Ok(changes),
        Err(error) => {
            warn!(
                "Agent Settings audit record failed; rolling back: {:?}",
                error
            );
            Err(
                match restore_agent_setting_changes(state, user_type_id, &changes) {
                    Rollback::Restored => match error {
                        AdminConfigToolError::Unauthorized => {
                            admin_config_native_failure(AdminConfigToolError::Unauthorized)
                        }
                        _ => NativeToolResult::failure("execution_failed", AUDIT_UNAVAILABLE),
                    },
                    Rollback::Superseded | Rollback::Failed => {
                        NativeToolResult::failure("execution_failed", ROLLBACK_INCOMPLETE)
                    }
                },
            )
        }
    }
}

/// Confirms a User Type exists before writing its overrides.
async fn check_user_type(
    internal: &InternalAgentClient,
    user_type_id: i32,
) -> std::result::Result<(), NativeToolResult> {
    match internal.user_type(user_type_id).await {
        Ok(_) => Ok(()),
        Err(error) if error.to_string().starts_with("backend returned 404") => {
            Err(NativeToolResult::failure(
                "validation_failed",
                format!("User Type not found: {}", user_type_id),
            ))
        }
        Err(error)
            if matches!(
                error.downcast_ref::<ToolExecutionError>(),
                Some(ToolExecutionError::Unauthorized)
            ) =>
        {
            Err(admin_config_native_failure(
                AdminConfigToolError::Unauthorized,
            ))
        }
        Err(_) => Err(NativeToolResult::failure(
            "execution_failed",
            "Could not confirm the User Type. Try again.",
        )),
    }
}

fn changed_keys(changes: &[AgentSettingChange]) -> Vec<String> {
    let mut keys = changes
        .iter()
        .map(|change| change.key.clone())
        .collect::<Vec<_>>();
    keys.sort();
    keys.dedup();
    keys
}

fn store_unavailable() -> NativeToolResult {
    NativeToolResult::failure(
        "execution_failed",
        "Sage's Agent Settings store is unavailable in this runtime.",
    )
}

/// `update_agent_settings`: global values or one User Type's overrides.
#[derive(Clone)]
pub(super) struct AdminAgentSettingsWriteTool {
    pub(super) internal: InternalAgentClient,
    pub(super) state: Option<WebAppState>,
    pub(super) auth: InternalAuthContext,
    pub(super) conversation_id: String,
    pub(super) traces: Arc<Mutex<Vec<ToolCallInfoResponse>>>,
    pub(super) affected_areas: Arc<Mutex<Vec<String>>>,
}

#[async_trait::async_trait]
impl Tool for AdminAgentSettingsWriteTool {
    fn name(&self) -> &str {
        "update_agent_settings"
    }

    fn description(&self) -> &str {
        "Update global or User-Type-specific Agent Settings, or revert User-Type overrides, atomically."
    }

    fn native_parameters(&self) -> Result<Value> {
        admin_config_direct_native_parameters("update_agent_settings")
    }

    async fn execute_native(&self, args: &ToolArgs) -> Result<NativeToolResult> {
        let update = match parse_update_agent_settings(args) {
            Ok(update) => update,
            Err(message) => return Ok(NativeToolResult::failure("invalid_arguments", message)),
        };
        let Some(state) = self.state.as_ref() else {
            return Ok(store_unavailable());
        };
        if let Some(user_type_id) = update.user_type_id {
            if let Err(failure) = check_user_type(&self.internal, user_type_id).await {
                return Ok(failure);
            }
        }
        if let Err(message) = validate_agent_setting_writes(state, &update.writes) {
            return Ok(NativeToolResult::failure("validation_failed", message));
        }
        let changes = match apply_and_record(
            state,
            &self.internal,
            &self.auth,
            &self.conversation_id,
            "update_agent_settings",
            update.user_type_id,
            &update.writes,
        )
        .await
        {
            Ok(changes) => changes,
            Err(failure) => return Ok(failure),
        };

        let requested = update
            .writes
            .iter()
            .map(|write| write.key().to_string())
            .collect::<Vec<_>>();
        let saved = match saved_values(state, update.user_type_id, &requested) {
            Ok(saved) => saved,
            Err(error) => return Ok(NativeToolResult::failure("execution_failed", error.message)),
        };
        let reverted_keys = changes
            .iter()
            .filter(|change| change.new_value.is_none())
            .map(|change| change.key.clone())
            .collect::<Vec<_>>();
        let response = InternalAdminConfigToolResponse {
            version: 1,
            tool: "update_agent_settings".to_string(),
            data: json!({
                "outcome": "succeeded",
                "validation": {"status": "valid"},
                "saved_values": saved,
                "changed_names": changed_keys(&changes),
                "reverted_keys": reverted_keys,
                "user_type_id": update.user_type_id,
                "affected_areas": ["agent_settings"],
            }),
            warnings: Vec::new(),
            generated_at: chrono::Utc::now().to_rfc3339(),
            secret_policy: json!({"mode": "masked"}),
        };
        Ok(admin_config_direct_result(
            "update_agent_settings",
            response,
            &self.traces,
            &self.affected_areas,
        ))
    }
}

/// `configure_instance`: the control plane applies Instance Settings, User
/// Types, and Onboarding Questions; Sage applies the guided Agent Settings.
#[derive(Clone)]
pub(super) struct AdminConfigureInstanceTool {
    pub(super) internal: InternalAgentClient,
    pub(super) state: Option<WebAppState>,
    pub(super) auth: InternalAuthContext,
    pub(super) conversation_id: String,
    pub(super) traces: Arc<Mutex<Vec<ToolCallInfoResponse>>>,
    pub(super) affected_areas: Arc<Mutex<Vec<String>>>,
}

#[async_trait::async_trait]
impl Tool for AdminConfigureInstanceTool {
    fn name(&self) -> &str {
        "configure_instance"
    }

    fn description(&self) -> &str {
        "Apply the complete guided first-setup configuration atomically after the Admin confirms it conversationally."
    }

    fn native_parameters(&self) -> Result<Value> {
        admin_config_direct_native_parameters("configure_instance")
    }

    async fn execute_native(&self, args: &ToolArgs) -> Result<NativeToolResult> {
        let mut payload = match build_admin_config_direct_payload("configure_instance", args) {
            Ok(payload) => payload,
            Err(error) => {
                return Ok(NativeToolResult::failure(
                    "invalid_arguments",
                    error.to_string(),
                ))
            }
        };
        let (writes, saved_rules) = match take_guided_agent_settings(&mut payload) {
            Ok(guided) => guided,
            Err(message) => return Ok(NativeToolResult::failure("validation_failed", message)),
        };
        let Some(state) = self.state.as_ref() else {
            return Ok(store_unavailable());
        };
        if let Err(message) = validate_agent_setting_writes(state, &writes) {
            return Ok(NativeToolResult::failure("validation_failed", message));
        }

        // Apply Agent Settings first so a control-plane rejection, the likely
        // failure, can restore them and leave the whole setup unapplied.
        let changes = match apply_agent_setting_writes(state, None, &writes) {
            Ok(changes) => changes,
            Err(error) => return Ok(NativeToolResult::failure("execution_failed", error.message)),
        };
        let mut response = match self
            .internal
            .admin_config_direct_tool(
                "configure-instance",
                &self.auth,
                &self.conversation_id,
                payload,
            )
            .await
        {
            Ok(response) => response,
            Err(error) => {
                return Ok(match restore_agent_setting_changes(state, None, &changes) {
                    Rollback::Restored => admin_config_native_failure(error),
                    Rollback::Superseded | Rollback::Failed => NativeToolResult::failure(
                        "partially_applied",
                        "Guided setup was rejected, but its behavior rules or forbidden topics could not be fully rolled back. Read the Agent Settings before retrying.",
                    ),
                });
            }
        };
        if changes.is_empty() {
            merge_guided_agent_settings(&mut response.data, &changes, saved_rules);
            return Ok(self.finish(response));
        }
        if let Err(error) = record_agent_settings_change(
            &self.internal,
            &self.auth,
            &self.conversation_id,
            "configure_instance",
            None,
            &changes,
        )
        .await
        {
            warn!(
                "guided Agent Settings audit failed; rolling back: {:?}",
                error
            );
            let message = match restore_agent_setting_changes(state, None, &changes) {
                Rollback::Restored => "Instance Settings, User Types, and Onboarding Questions were saved, but behavior rules and forbidden topics were not, because that change could not be recorded in the Audit Log. Retry them with update_agent_settings.",
                Rollback::Superseded | Rollback::Failed => "Instance Settings, User Types, and Onboarding Questions were saved. Behavior rules and forbidden topics could not be recorded in the Audit Log, and rolling them back did not complete. Read the Agent Settings before retrying.",
            };
            // The control-plane part is committed: refresh its areas and show it.
            if let Some(object) = response.data.as_object_mut() {
                object.insert("outcome".to_string(), Value::from("partially_applied"));
            }
            let _ = self.finish(response);
            return Ok(NativeToolResult::failure("partially_applied", message));
        }

        merge_guided_agent_settings(&mut response.data, &changes, saved_rules);
        Ok(self.finish(response))
    }
}

impl AdminConfigureInstanceTool {
    fn finish(&self, response: InternalAdminConfigToolResponse) -> NativeToolResult {
        admin_config_direct_result(
            "configure_instance",
            response,
            &self.traces,
            &self.affected_areas,
        )
    }
}

/// Adds the Sage-applied Agent Settings to the control plane's result.
fn merge_guided_agent_settings(
    data: &mut Value,
    changes: &[AgentSettingChange],
    saved: serde_json::Map<String, Value>,
) {
    let Some(object) = data.as_object_mut() else {
        return;
    };
    if let Some(Value::Object(setup)) = object.get_mut("saved_setup") {
        setup.extend(saved);
    }
    let mut changed = object
        .get("changed_names")
        .and_then(Value::as_array)
        .map(|names| {
            names
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    changed.extend(
        changed_keys(changes)
            .into_iter()
            .map(|key| format!("agent_settings.{}", key)),
    );
    changed.sort();
    object.insert("changed_names".to_string(), Value::from(changed));
    if changes.is_empty() {
        return;
    }
    let mut areas = object
        .get("affected_areas")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if !areas.iter().any(|area| area == "agent_settings") {
        areas.insert(1.min(areas.len()), Value::from("agent_settings"));
    }
    object.insert("affected_areas".to_string(), Value::Array(areas));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(value: Value) -> ToolArgs {
        ToolArgs::from_json_object(&value).expect("object args")
    }

    #[test]
    fn update_arguments_become_one_ordered_scope() {
        let update = parse_update_agent_settings(&args(json!({
            "updates": {"top_k": 6, "temperature": "0.4", "web_search_default": true},
            "revert_keys": ["prompt_tone", "prompt_tone"],
            "user_type_id": 3,
        })))
        .unwrap();

        assert_eq!(update.user_type_id, Some(3));
        assert_eq!(
            update.writes,
            vec![
                AgentSettingWrite::Set {
                    key: "temperature".into(),
                    value: "0.4".into()
                },
                AgentSettingWrite::Set {
                    key: "top_k".into(),
                    value: "6".into()
                },
                AgentSettingWrite::Set {
                    key: "web_search_default".into(),
                    value: "true".into()
                },
                AgentSettingWrite::Revert {
                    key: "prompt_tone".into()
                },
            ]
        );
    }

    #[test]
    fn update_arguments_reject_ambiguous_or_empty_calls() {
        for (call, message) in [
            (
                json!({}),
                "At least one Agent Setting operation is required",
            ),
            (
                json!({"revert_keys": ["temperature"]}),
                "Only User Type overrides can be reverted",
            ),
            (
                json!({"user_type_id": 2, "updates": {"temperature": "0.2"}, "revert_keys": ["temperature"]}),
                "temperature cannot be updated and reverted in the same call",
            ),
            (
                json!({"updates": {"prompt_rules": ["a"]}}),
                "The value for prompt_rules must be a string",
            ),
            (
                json!({"updates": "temperature=0.2"}),
                "updates must be an object of setting keys and values",
            ),
            (
                json!({"updates": {"temperature": "0.2"}, "user_type_id": 0}),
                "user_type_id must be a positive integer",
            ),
        ] {
            assert_eq!(
                parse_update_agent_settings(&args(call)).unwrap_err(),
                message
            );
        }
    }

    #[test]
    fn guided_rules_leave_the_control_plane_payload_and_keep_required_rules() {
        let mut payload = json!({
            "settings": {"instance_name": "Freedom Network"},
            "user_types": [],
            "onboarding_questions": [],
            "behavior_rules": ["  Prioritize verified support steps.  ", "State uncertainty plainly."],
            "forbidden_topics": ["Never invent contact details."],
        });

        let (writes, saved) = take_guided_agent_settings(&mut payload).unwrap();

        assert!(payload.get("behavior_rules").is_none());
        assert!(payload.get("forbidden_topics").is_none());
        assert_eq!(
            Value::Object(saved),
            json!({
                "behavior_rules": ["Prioritize verified support steps.", "State uncertainty plainly."],
                "forbidden_topics": ["Never invent contact details."],
            })
        );
        assert_eq!(
            writes[0],
            AgentSettingWrite::Set {
                key: "prompt_forbidden".into(),
                value: r#"["Never invent contact details."]"#.into(),
            }
        );
        let AgentSettingWrite::Set { key, value } = &writes[1] else {
            panic!("prompt_rules should be set");
        };
        assert_eq!(key, "prompt_rules");
        let rules: Vec<String> = serde_json::from_str(value).unwrap();
        assert_eq!(rules[0], "Prioritize verified support steps.");
        assert_eq!(rules[1], "State uncertainty plainly.");
        assert_eq!(rules.len(), 2 + DEFAULT_PROMPT_RULES.len());
        assert!(DEFAULT_PROMPT_RULES
            .iter()
            .all(|rule| rules.iter().any(|saved| saved == rule)));
    }

    #[test]
    fn empty_guided_lists_leave_existing_rules_alone() {
        let mut payload = json!({
            "settings": {"instance_name": "Freedom Network"},
            "behavior_rules": [],
            "forbidden_topics": ["Never invent contact details."],
        });

        let (writes, saved) = take_guided_agent_settings(&mut payload).unwrap();

        assert_eq!(
            writes,
            vec![AgentSettingWrite::Set {
                key: "prompt_forbidden".into(),
                value: r#"["Never invent contact details."]"#.into(),
            }]
        );
        assert_eq!(
            Value::Object(saved),
            json!({"forbidden_topics": ["Never invent contact details."]})
        );
        let (none, _) = take_guided_agent_settings(&mut json!({"settings": {}})).unwrap();
        assert!(none.is_empty());
    }

    #[test]
    fn guided_rules_are_validated() {
        for (payload, message) in [
            (
                json!({"behavior_rules": ["ok", "  "]}),
                "behavior_rules cannot contain blank values",
            ),
            (
                json!({"forbidden_topics": "politics"}),
                "forbidden_topics must be an array of strings",
            ),
            (
                json!({"behavior_rules": vec!["rule"; 9]}),
                "behavior_rules accepts at most 8 items",
            ),
        ] {
            let mut payload = payload;
            assert_eq!(
                take_guided_agent_settings(&mut payload).unwrap_err(),
                message
            );
        }
    }

    #[test]
    fn guided_agent_settings_join_the_control_plane_result() {
        let mut data = json!({
            "outcome": "succeeded",
            "saved_setup": {"settings": {"instance_name": "Freedom Network"}},
            "changed_names": ["instance_settings.instance_name"],
            "affected_areas": ["instance_settings", "user_types", "onboarding_questions"],
        });
        let changes = vec![AgentSettingChange {
            key: "prompt_rules".into(),
            old_value: Some("[]".into()),
            new_value: Some(r#"["rule"]"#.into()),
        }];

        let saved = json!({"behavior_rules": ["rule"]});
        merge_guided_agent_settings(&mut data, &changes, saved.as_object().unwrap().clone());

        assert_eq!(data["saved_setup"]["behavior_rules"], json!(["rule"]));
        assert_eq!(
            data["changed_names"],
            json!([
                "agent_settings.prompt_rules",
                "instance_settings.instance_name"
            ])
        );
        assert_eq!(
            data["affected_areas"],
            json!([
                "instance_settings",
                "agent_settings",
                "user_types",
                "onboarding_questions"
            ])
        );
    }

    #[test]
    fn unchanged_guided_rules_do_not_claim_agent_settings_changed() {
        let mut data = json!({
            "saved_setup": {},
            "changed_names": ["instance_settings.instance_name"],
            "affected_areas": ["instance_settings", "user_types", "onboarding_questions"],
        });

        merge_guided_agent_settings(&mut data, &[], serde_json::Map::new());

        assert_eq!(
            data["changed_names"],
            json!(["instance_settings.instance_name"])
        );
        assert_eq!(
            data["affected_areas"],
            json!(["instance_settings", "user_types", "onboarding_questions"])
        );
    }

    fn admin() -> InternalAuthContext {
        InternalAuthContext {
            id: 1,
            kind: "admin".to_string(),
            approved: true,
            pubkey: Some("admin-pubkey".to_string()),
            email: None,
            name: None,
            user_type_id: None,
            dev_mode: false,
        }
    }

    async fn recording_backend(
        status: StatusCode,
    ) -> (
        InternalAgentClient,
        Arc<Mutex<Vec<(String, Value)>>>,
        tokio::task::JoinHandle<()>,
    ) {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let app = Router::new().route(
            "/internal/agent/admin-config/{endpoint}",
            post({
                let seen = seen.clone();
                move |Path(endpoint): Path<String>, Json(payload): Json<Value>| {
                    let seen = seen.clone();
                    async move {
                        seen.lock().unwrap().push((endpoint, payload));
                        (
                            status,
                            Json(json!({
                                "version": 1,
                                "tool": "record_agent_settings_change",
                                "data": {"recorded": 1},
                                "warnings": [],
                                "generated_at": "2026-10-23T00:00:00+00:00",
                                "secret_policy": {"mode": "masked"}
                            })),
                        )
                    }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let internal =
            InternalAgentClient::new(Client::new(), format!("http://{addr}"), "test-token".into());
        (internal, seen, server)
    }

    #[tokio::test]
    async fn changes_are_recorded_with_actor_and_conversation_provenance() {
        let (internal, seen, server) = recording_backend(StatusCode::OK).await;
        let changes = vec![
            AgentSettingChange {
                key: "temperature".into(),
                old_value: Some("0.1".into()),
                new_value: Some("0.4".into()),
            },
            AgentSettingChange {
                key: "prompt_tone".into(),
                old_value: Some("Warm.".into()),
                new_value: None,
            },
        ];

        record_agent_settings_change(
            &internal,
            &admin(),
            "conversation-1",
            "update_agent_settings",
            Some(5),
            &changes,
        )
        .await
        .expect("record succeeds");
        server.abort();

        let seen = seen.lock().unwrap();
        assert_eq!(seen[0].0, "record-agent-settings-change");
        let payload = &seen[0].1;
        assert_eq!(payload["actor"]["type"], "admin");
        assert_eq!(payload["conversation_id"], "conversation-1");
        assert_eq!(payload["tool_name"], "update_agent_settings");
        assert_eq!(payload["user_type_id"], 5);
        assert_eq!(
            payload["changes"],
            json!([
                {"key": "temperature", "old_value": "0.1", "new_value": "0.4"},
                {"key": "prompt_tone", "old_value": "Warm.", "new_value": null},
            ])
        );
    }

    #[tokio::test]
    async fn writes_need_the_sage_store_and_never_call_the_control_plane_without_it() {
        let (internal, seen, server) = recording_backend(StatusCode::OK).await;
        let sinks = (
            Arc::new(Mutex::new(Vec::new())),
            Arc::new(Mutex::new(Vec::new())),
        );
        let update = AdminAgentSettingsWriteTool {
            internal: internal.clone(),
            state: None,
            auth: admin(),
            conversation_id: "conversation-1".into(),
            traces: sinks.0.clone(),
            affected_areas: sinks.1.clone(),
        };
        let configure = AdminConfigureInstanceTool {
            internal,
            state: None,
            auth: admin(),
            conversation_id: "conversation-1".into(),
            traces: sinks.0.clone(),
            affected_areas: sinks.1.clone(),
        };

        let updated = update
            .execute_native(&args(json!({"updates": {"temperature": "0.4"}})))
            .await
            .unwrap();
        let configured = configure
            .execute_native(&args(json!({
                "settings": {"instance_name": "Freedom Network"},
                "behavior_rules": ["rule"],
            })))
            .await
            .unwrap();
        server.abort();

        assert_eq!(updated.model_value()["error"]["code"], "execution_failed");
        assert_eq!(
            configured.model_value()["error"]["code"],
            "execution_failed"
        );
        let blank_rule = configure
            .execute_native(&args(
                json!({"settings": {"instance_name": "X"}, "behavior_rules": [" "]}),
            ))
            .await
            .unwrap();
        assert_eq!(
            blank_rule.model_value()["error"]["code"],
            "validation_failed"
        );
        assert!(seen.lock().unwrap().is_empty());
        assert!(sinks.1.lock().unwrap().is_empty());
    }
}
