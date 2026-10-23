//! Admin Config-only reads of the retained, masked control-plane Audit Log.
use super::*;

#[derive(Clone)]
pub(super) struct AdminAuditLogReadTool {
    pub(super) internal: InternalAgentClient,
    pub(super) auth: InternalAuthContext,
    pub(super) config_enabled: bool,
    pub(super) traces: Arc<Mutex<Vec<ToolCallInfoResponse>>>,
}

#[async_trait::async_trait]
impl Tool for AdminAuditLogReadTool {
    fn name(&self) -> &str {
        "read_audit_log"
    }
    fn description(&self) -> &str {
        "Read retained settings audit records with stable IDs and filters. A page may contain fewer records than limit because of the byte budget. When the user requests a count, KEEP CALLING with next_cursor and identical filters until that count is reached or next_cursor is null; never present the first partial page as the complete answer. Use table to distinguish admin_config_tools action summaries from per-setting rows such as ai_config and instance_settings; do not double-count a summary as another setting change. Public branding has marked before/after excerpts; safe numeric settings are shown. Prompts, deployment values and unknown historical values are redacted. Coverage describes retained records only."
    }
    fn native_parameters(&self) -> Result<Value> {
        Ok(json!({"type":"object", "properties": {
            "start_time":{"type":"string","description":"Inclusive ISO 8601 time with timezone."},
            "end_time":{"type":"string","description":"Exclusive ISO 8601 time with timezone."},
            "actor_id":{"type":"string","description":"Exact stored actor identifier (normally Admin public key)."},
            "action_source":{"type":"string","description":"Exact source, e.g. sage_conversation or admin_ui."},
            "config_key":{"type":"string","description":"Exact recorded key; User Type keys include :type_ID."},
            "cursor":{"type":"string","description":"Opaque next_cursor from the previous page with identical filters."},
            "limit":{"type":"integer","minimum":1,"maximum":20,"description":"Maximum records; byte budget may return fewer."}
        }, "additionalProperties":false}))
    }
    async fn execute_native(&self, args: &ToolArgs) -> Result<NativeToolResult> {
        if !self.config_enabled
            || self.auth.kind != "admin"
            || !self.auth.approved
            || self
                .auth
                .pubkey
                .as_deref()
                .is_none_or(|key| key.trim().is_empty())
        {
            return Ok(NativeToolResult::failure(
                "unauthorized",
                "Audit reads require an approved Admin with Config enabled.",
            ));
        }
        let allowed = [
            "start_time",
            "end_time",
            "actor_id",
            "action_source",
            "config_key",
            "cursor",
            "limit",
        ];
        if args.keys().any(|key| !allowed.contains(&key.as_str())) {
            return Ok(NativeToolResult::failure(
                "invalid_arguments",
                "Unsupported audit filter.",
            ));
        }
        let mut payload: serde_json::Map<String, Value> = args
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        payload.insert("actor".into(), json!(self.auth));
        let request = self
            .internal
            .http
            .post(format!(
                "{}/internal/agent/admin-config/read-audit-log",
                self.internal.backend_url
            ))
            .header(
                "X-Internal-Agent-Token",
                &self.internal.internal_agent_token,
            )
            .json(&payload);
        let (status, value) = match self.internal.send_value_with_status(request).await {
            Ok(response) => response,
            Err(_) => {
                return Ok(NativeToolResult::failure(
                    "execution_failed",
                    "Audit read is unavailable.",
                ));
            }
        };
        if matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN) {
            return Ok(NativeToolResult::failure(
                "unauthorized",
                "Admin access is no longer available.",
            ));
        }
        if matches!(
            status,
            StatusCode::BAD_REQUEST | StatusCode::UNPROCESSABLE_ENTITY
        ) {
            return Ok(NativeToolResult::failure(
                "invalid_arguments",
                "Invalid audit filters or cursor; use timezone-aware times and the original cursor filters.",
            ));
        }
        if !status.is_success()
            || serde_json::to_vec(&value)?.len() > 1200
            || !value.get("records").is_some_and(Value::is_array)
            || !value.get("coverage").is_some_and(Value::is_object)
            || !value
                .get("next_cursor")
                .is_some_and(|cursor| cursor.is_null() || cursor.is_string())
        {
            return Ok(NativeToolResult::failure(
                "execution_failed",
                "Audit read returned an invalid bounded page.",
            ));
        }
        if let Ok(mut traces) = self.traces.lock() {
            traces.push(ToolCallInfoResponse {
                tool_id: Uuid::new_v4().to_string(),
                tool_name: self.name().into(),
                query: None,
                output_summary: Some(format!(
                    "Read {} retained audit records.",
                    value["records"].as_array().map_or(0, Vec::len)
                )),
                warnings: vec![],
                metadata: json!({"source":"control_plane_audit"}),
                guarded: false,
            });
        }
        Ok(NativeToolResult::success(value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn admin() -> InternalAuthContext {
        InternalAuthContext {
            id: 1,
            kind: "admin".into(),
            approved: true,
            pubkey: Some("admin-key".into()),
            email: None,
            name: None,
            user_type_id: None,
            dev_mode: false,
        }
    }
    fn tool(auth: InternalAuthContext, config_enabled: bool) -> AdminAuditLogReadTool {
        AdminAuditLogReadTool {
            internal: InternalAgentClient::new(
                Client::new(),
                "http://127.0.0.1:1".into(),
                "test-token".into(),
            ),
            auth,
            config_enabled,
            traces: Arc::default(),
        }
    }
    #[tokio::test]
    async fn audit_read_denies_non_admin_impersonated_disabled_or_unapproved_execution() {
        let mut actors = vec![(admin(), false)];
        let mut user = admin();
        user.kind = "user".into();
        actors.push((user, true));
        let mut unapproved = admin();
        unapproved.approved = false;
        actors.push((unapproved, true));
        let mut missing = admin();
        missing.pubkey = None;
        actors.push((missing, true));
        for (actor, enabled) in actors {
            let result = tool(actor, enabled)
                .execute_native(&ToolArgs::from_json_object(&json!({})).unwrap())
                .await
                .unwrap();
            assert!(
                matches!(result, NativeToolResult::Failure { ref code, .. } if code == "unauthorized")
            );
        }
    }
    struct UiFixture {
        state: WebAppState,
        base: String,
        token: String,
        schema: String,
        mode: Arc<std::sync::atomic::AtomicU8>,
        seen: Arc<Mutex<Vec<Value>>>,
        servers: Vec<tokio::task::JoinHandle<()>>,
    }
    impl Drop for UiFixture {
        fn drop(&mut self) {
            for server in &self.servers {
                server.abort();
            }
            use diesel::connection::SimpleConnection;
            self.state
                .db
                .lock()
                .unwrap()
                .batch_execute(&format!("DROP SCHEMA {} CASCADE", self.schema))
                .unwrap();
        }
    }
    async fn serve(app: Router) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (base, task)
    }
    impl UiFixture {
        async fn new() -> Self {
            use diesel::connection::SimpleConnection;
            let url = std::env::var("AUDIT_TEST_DATABASE_URL")
                .expect("set AUDIT_TEST_DATABASE_URL to the isolated local synthetic database");
            let parsed = reqwest::Url::parse(&url).expect("test database URL");
            assert!(
                matches!(parsed.host_str(), Some("127.0.0.1" | "localhost" | "[::1]")),
                "audit integration tests require a local synthetic database"
            );
            let mut conn = PgConnection::establish(&url).expect("synthetic test database");
            let schema = format!("audit_test_{}", Uuid::new_v4().simple());
            conn.batch_execute(&format!("CREATE SCHEMA {schema}; SET search_path TO {schema};
                CREATE TABLE ai_config (key varchar PRIMARY KEY, value text NOT NULL, value_type varchar NOT NULL,
                    category varchar NOT NULL, description text, updated_at timestamptz NOT NULL DEFAULT NOW());
                CREATE TABLE ai_config_user_type_overrides (id uuid PRIMARY KEY, ai_config_key varchar NOT NULL,
                    user_type_id integer NOT NULL, value text NOT NULL, updated_at timestamptz NOT NULL DEFAULT NOW(),
                    UNIQUE (ai_config_key, user_type_id));
                INSERT INTO ai_config (key,value,value_type,category) VALUES ('temperature','0.1','number','parameter');")).unwrap();
            let db = Arc::new(Mutex::new(conn));
            let mode = Arc::new(std::sync::atomic::AtomicU8::new(0));
            let seen = Arc::new(Mutex::new(Vec::new()));
            let backend = Router::new()
                .route("/internal/agent/admins/by-pubkey/{pubkey}", get(|| async {
                    Json(json!({"id":1,"pubkey":"admin-key","session_nonce":7}))
                }))
                .route("/internal/agent/user-types/{id}", get(|| async {
                    Json(json!({"id":3,"name":"Member","display_order":0}))
                }))
                .route("/internal/agent/admin-config/record-agent-settings-change", post({
                    let mode = mode.clone(); let seen = seen.clone(); let db = db.clone();
                    move |headers: HeaderMap, Json(payload): Json<Value>| {
                        let mode = mode.clone(); let seen = seen.clone(); let db = db.clone();
                        async move {
                            assert_eq!(headers["X-Internal-Agent-Token"], "test-token");
                            seen.lock().unwrap().push(payload);
                            let mode = mode.load(std::sync::atomic::Ordering::SeqCst);
                            if mode == 3 {
                                diesel::sql_query("UPDATE ai_config SET value = '0.9' WHERE key = 'temperature'")
                                    .execute(&mut *db.lock().unwrap()).unwrap();
                            }
                            let status = match mode { 0 => StatusCode::OK, 2 => StatusCode::FORBIDDEN, _ => StatusCode::SERVICE_UNAVAILABLE };
                            (status, Json(json!({"version":1,"tool":"record_agent_settings_change","data":{"recorded":1},
                                "warnings":[],"generated_at":"2026-10-23T00:00:00Z","secret_policy":{"mode":"masked"}})))
                        }
                    }
                }));
            let (backend_url, backend_server) = serve(backend).await;
            let http = Client::new();
            let state = WebAppState {
                config: Config {
                    tinfoil_api_url: String::new(),
                    tinfoil_api_key: None,
                    maple_api_url: String::new(),
                    maple_api_key: None,
                    tinfoil_model: "test-model".into(),
                    tinfoil_reasoning_effort: NativeReasoningEffort::Low,
                    tinfoil_embedding_model: String::new(),
                    tinfoil_vision_model: String::new(),
                    database_url: url,
                    messenger_type: crate::config::MessengerType::Signal,
                    signal_phone_number: None,
                    signal_allowed_users: vec![],
                    signal_cli_host: None,
                    signal_cli_port: 0,
                    marmot_binary: String::new(),
                    marmot_relays: vec![],
                    marmot_state_dir: String::new(),
                    marmot_allowed_pubkeys: vec![],
                    marmot_auto_accept_welcomes: false,
                    brave_api_key: None,
                    workspace_path: String::new(),
                    http_port: 0,
                },
                web_config: EnclaveWebConfig {
                    http_port: 0,
                    backend_url: backend_url.clone(),
                    internal_agent_token: "test-token".into(),
                    secret_key: "test-secret".into(),
                    allowed_origins: vec![],
                    frontend_url: None,
                    user_session_cookie_name: "user".into(),
                    admin_session_cookie_name: "admin".into(),
                    csrf_cookie_name: "csrf".into(),
                },
                internal: InternalAgentClient::new(http.clone(), backend_url, "test-token".into()),
                http,
                db,
                user_lookups: Arc::new(user_lookup::PendingLookups::default()),
            };
            let app = Router::new()
                .route(
                    "/admin/ai-config/{key}",
                    get(admin_ai_config_key).put(admin_ai_config_key_update),
                )
                .route(
                    "/admin/ai-config/user-type/{id}/{key}",
                    put(admin_ai_config_user_type_update).delete(admin_ai_config_user_type_delete),
                )
                .route(
                    "/admin/ai-config/user-type/{id}",
                    get(admin_ai_config_user_type),
                )
                .with_state(state.clone());
            let (base, ui_server) = serve(app).await;
            let serializer = timed_serializer_with_signer(
                default_builder("test-secret".to_string())
                    .with_salt(ADMIN_SESSION_SALT)
                    .build()
                    .into_timestamp_signer(),
                PythonURLSafeEncoding,
            );
            let token = serializer
                .sign(&json!({"admin_id":1,"pubkey":"admin-key","type":"admin","session_nonce":7}))
                .unwrap();
            Self {
                state,
                base,
                token,
                schema,
                mode,
                seen,
                servers: vec![backend_server, ui_server],
            }
        }
        async fn request(&self, method: Method, path: &str, body: Value) -> (StatusCode, Value) {
            let response = self
                .state
                .http
                .request(method, format!("{}{path}", self.base))
                .bearer_auth(&self.token)
                .json(&body)
                .send()
                .await
                .unwrap();
            (response.status(), response.json().await.unwrap())
        }
        async fn value(&self) -> String {
            let (status, body) = self
                .request(Method::GET, "/admin/ai-config/temperature", json!(null))
                .await;
            assert_eq!(status, StatusCode::OK);
            body["value"].as_str().unwrap().to_string()
        }
    }

    #[tokio::test]
    #[ignore = "requires isolated local PostgreSQL via AUDIT_TEST_DATABASE_URL"]
    async fn audit_ui_writes_record_provenance_and_preserve_rollback_and_concurrent_edits() {
        use std::sync::atomic::Ordering;
        let fixture = UiFixture::new().await;
        let path = "/admin/ai-config/temperature";
        let (status, _) = fixture
            .request(Method::PUT, path, json!({"value":"0.4"}))
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(fixture.value().await, "0.4");
        {
            let records = fixture.seen.lock().unwrap();
            assert_eq!(records.len(), 1);
            assert_eq!(records[0]["tool_name"], "admin_ui_update_agent_settings");
            assert_eq!(
                records[0]["changes"],
                json!([{"key":"temperature","old_value":"0.1","new_value":"0.4"}])
            );
        }
        fixture.mode.store(1, Ordering::SeqCst);
        let (status, body) = fixture
            .request(Method::PUT, path, json!({"value":"0.6"}))
            .await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert!(body["detail"].as_str().unwrap().contains("not changed"));
        assert_eq!(fixture.value().await, "0.4");
        fixture.mode.store(2, Ordering::SeqCst);
        let (status, _) = fixture
            .request(Method::PUT, path, json!({"value":"0.7"}))
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(fixture.value().await, "0.4");
        fixture.mode.store(3, Ordering::SeqCst);
        let (status, body) = fixture
            .request(Method::PUT, path, json!({"value":"0.8"}))
            .await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert!(body["detail"].as_str().unwrap().contains("may still"));
        assert_eq!(fixture.value().await, "0.9");
    }
    #[tokio::test]
    async fn audit_native_read_forwards_filters_bounds_results_and_keeps_traces_clean() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let mode = Arc::new(std::sync::atomic::AtomicU8::new(0));
        let app = Router::new().route("/internal/agent/admin-config/read-audit-log", post({
            let seen = seen.clone(); let mode = mode.clone();
            move |headers: HeaderMap, Json(body): Json<Value>| {
                let seen = seen.clone(); let mode = mode.clone();
                async move {
                    assert_eq!(headers["X-Internal-Agent-Token"], "test-token");
                    seen.lock().unwrap().push(body);
                    let mode = mode.load(std::sync::atomic::Ordering::SeqCst);
                    let status = if mode == 2 { StatusCode::FORBIDDEN } else { StatusCode::OK };
                    let record = if mode == 1 { "sensitive-backend-detail".repeat(100) } else { "public-branding-excerpt".into() };
                    (status, Json(json!({"records":[{"id":17,"before":{"text":record,"excerpt":false},"after":{"redacted":true}}],
                        "next_cursor":"next-page", "coverage":{"scope":"retained_audit","matched":9,"returned":1}})))
                }
            }
        }));
        let (base, server) = serve(app).await;
        let mut tool = tool(admin(), true);
        tool.internal.backend_url = base;
        let args = ToolArgs::from_json_object(
            &json!({"action_source":"admin_ui","limit":1,"cursor":"opaque-cursor"}),
        )
        .unwrap();
        let result = tool.execute_native(&args).await.unwrap();
        assert!(result.is_success());
        assert_eq!(result.model_value()["records"][0]["id"], 17);
        assert_eq!(result.model_value()["next_cursor"], "next-page");
        assert!(serde_json::to_vec(&result.model_value()).unwrap().len() <= 1200);
        {
            let sent = seen.lock().unwrap();
            assert_eq!(sent[0]["actor"]["pubkey"], "admin-key");
            assert_eq!(sent[0]["action_source"], "admin_ui");
            assert_eq!(sent[0]["cursor"], "opaque-cursor");
        }
        let traces = serde_json::to_string(&*tool.traces.lock().unwrap()).unwrap();
        assert!(!traces.contains("public-branding-excerpt"));
        assert!(!traces.contains("opaque-cursor"));
        mode.store(1, std::sync::atomic::Ordering::SeqCst);
        let result = tool.execute_native(&args).await.unwrap();
        assert!(!result.is_success());
        assert!(!result
            .model_value()
            .to_string()
            .contains("sensitive-backend-detail"));
        mode.store(2, std::sync::atomic::Ordering::SeqCst);
        assert!(
            matches!(tool.execute_native(&args).await.unwrap(), NativeToolResult::Failure { code, .. } if code == "unauthorized")
        );
        let injected = ToolArgs::from_json_object(&json!({"actor":{"id":99}})).unwrap();
        assert!(
            matches!(tool.execute_native(&injected).await.unwrap(), NativeToolResult::Failure { code, .. } if code == "invalid_arguments")
        );
        assert_eq!(seen.lock().unwrap().len(), 3);
        server.abort();
    }

    #[tokio::test]
    #[ignore = "requires isolated local PostgreSQL via AUDIT_TEST_DATABASE_URL"]
    async fn audit_user_type_put_delete_rollback_and_agent_writes_share_provenance_path() {
        use std::sync::atomic::Ordering;
        let fixture = UiFixture::new().await;
        let path = "/admin/ai-config/user-type/3/temperature";
        let (status, body) = fixture
            .request(Method::PUT, path, json!({"value":"0.5"}))
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["value"], "0.5");
        assert_eq!(body["is_override"], true);
        fixture.mode.store(1, Ordering::SeqCst);
        let (status, _) = fixture.request(Method::DELETE, path, json!(null)).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        let (_, body) = fixture
            .request(Method::GET, "/admin/ai-config/user-type/3", json!(null))
            .await;
        assert_eq!(body["parameters"][0]["value"], "0.5");
        fixture.mode.store(0, Ordering::SeqCst);
        let (status, _) = fixture.request(Method::DELETE, path, json!(null)).await;
        assert_eq!(status, StatusCode::OK);
        let (_, body) = fixture
            .request(Method::GET, "/admin/ai-config/user-type/3", json!(null))
            .await;
        assert_eq!(body["parameters"][0]["value"], "0.1");
        assert_eq!(body["parameters"][0]["is_override"], false);
        {
            let seen = fixture.seen.lock().unwrap();
            assert_eq!(seen[0]["user_type_id"], 3);
            assert_eq!(seen[0]["changes"][0]["old_value"], Value::Null);
            assert_eq!(seen[2]["changes"][0]["new_value"], Value::Null);
        }
        let agent = agent_settings_writes::AdminAgentSettingsWriteTool {
            internal: fixture.state.internal.clone(),
            state: Some(fixture.state.clone()),
            auth: admin(),
            conversation_id: "conversation-1".into(),
            traces: Arc::default(),
            affected_areas: Arc::default(),
        };
        let args = ToolArgs::from_json_object(&json!({"updates":{"temperature":"0.6"}})).unwrap();
        assert!(agent.execute_native(&args).await.unwrap().is_success());
        assert_eq!(fixture.value().await, "0.6");
        {
            let seen = fixture.seen.lock().unwrap();
            assert_eq!(seen[3]["tool_name"], "update_agent_settings");
            assert_eq!(seen[3]["conversation_id"], "conversation-1");
        }
        fixture.mode.store(1, Ordering::SeqCst);
        let args = ToolArgs::from_json_object(&json!({"updates":{"temperature":"0.7"}})).unwrap();
        assert!(!agent.execute_native(&args).await.unwrap().is_success());
        assert_eq!(fixture.value().await, "0.6");
        let (status, _) = fixture
            .request(Method::PUT, path, json!({"value":"not-a-number"}))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
}
