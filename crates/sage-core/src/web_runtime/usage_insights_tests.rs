use super::*;
use diesel::{connection::SimpleConnection, Connection};
use serde_json::json;

fn fixture_connection() -> Option<PgConnection> {
    let Ok(url) = std::env::var("SAGE_USAGE_TEST_DATABASE_URL") else {
        eprintln!("SKIP isolated usage PG fixture: set SAGE_USAGE_TEST_DATABASE_URL");
        return None;
    };
    let mut conn = PgConnection::establish(&url).expect("connect synthetic local PG");
    conn.begin_test_transaction().unwrap();
    // Connection-local temporary tables shadow public names; rollback removes everything.
    conn.batch_execute(
        "CREATE TEMP TABLE web_sessions (id uuid PRIMARY KEY, agent_id uuid NOT NULL,
         owner_type text NOT NULL, owner_id text NOT NULL);
         CREATE TEMP TABLE messages (id uuid PRIMARY KEY, agent_id uuid NOT NULL,
         user_id text NOT NULL, role text NOT NULL, created_at timestamptz NOT NULL,
         tool_results jsonb);
         INSERT INTO web_sessions VALUES
         ('00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000011','user','1');
         INSERT INTO messages VALUES
         ('00000000-0000-0000-0000-000000000101','00000000-0000-0000-0000-000000000011','user:1','user','2026-03-08T06:00:00Z',NULL),
         ('00000000-0000-0000-0000-000000000102','00000000-0000-0000-0000-000000000011','user:1','assistant','2026-03-08T07:00:00Z',NULL),
         ('00000000-0000-0000-0000-000000000103','00000000-0000-0000-0000-000000000011','user:1','user','2026-03-09T05:00:00Z',NULL);",
    ).unwrap();
    Some(conn)
}

fn with_database(test: impl FnOnce(&mut PgConnection)) {
    if let Some(mut conn) = fixture_connection() {
        test(&mut conn);
    }
}

fn arguments() -> Value {
    json!({"start":"2026-03-08T06:00:00Z","end":"2026-03-09T05:00:00Z",
        "timezone":"America/Chicago","group_by":"day"})
}

#[test]
fn retained_counts_use_half_open_utc_interval_and_local_calendar_day() {
    with_database(|conn| {
        let result = query_usage(conn, &arguments(), &["1".into()]).unwrap();
        assert_eq!(result["rows"][0]["key"], "2026-03-08");
        assert_eq!(result["rows"][0]["human_messages"], 1);
        assert_eq!(result["rows"][0]["assistant_messages"], 1);
        assert_eq!(result["rows"][0]["active_users"], 1);
        assert_eq!(result["rows"][0]["active_conversations"], 1);
        assert_eq!(result["rows"][0]["tokens"], json!([null, null, null]));
        assert_eq!(result["rows"][0]["token_coverage"], json!([0, 0, 0]));
        assert_eq!(result["rows"][0]["assistant_with_usage"], 0);
        assert!(result["next_cursor"].is_null());
        assert!(serde_json::to_vec(&result).unwrap().len() <= 1200);
    });
}

#[test]
fn provider_observations_deduplicate_attempts_and_preserve_sparse_coverage() {
    with_database(|conn| {
        conn.batch_execute(r#"UPDATE messages SET tool_results='{"conversation_trace":{"trace_deltas":[
            {"kind":"timing","title":"Model usage","metadata":{"step":0,"attempt":0,"prompt_tokens":10,"total_tokens":12}},
            {"kind":"timing","title":"Model usage","metadata":{"step":0,"attempt":0,"prompt_tokens":10,"total_tokens":12}},
            {"kind":"timing","title":"Model usage","metadata":{"step":0,"attempt":1,"completion_tokens":3,"total_tokens":8}},
            {"kind":"timing","title":"Model request","metadata":{"step":0,"attempt":2,"total_tokens":999}}
        ]}}' WHERE role='assistant'"#).unwrap();
        let result = query_usage(conn, &arguments(), &["1".into()]).unwrap();
        let row = &result["rows"][0];
        assert_eq!(row["tokens"], json!([10, 3, 20]));
        assert_eq!(row["token_coverage"], json!([1, 1, 2]));
        assert_eq!(row["assistant_with_usage"], 1);
        assert_eq!(row["observation_records"], 1);
        assert_eq!(row["observations"], 2);
        assert_eq!(row["duplicates"], 1);
    });
}

#[test]
fn model_pages_distinguish_requested_message_model_observation_model_and_unknown() {
    with_database(|conn| {
        conn.batch_execute(
            r#"UPDATE messages SET tool_results='{"model":"fixture-model","model_source":"request",
        "conversation_trace":{"trace_deltas":[{"kind":"timing","title":"Model usage","metadata":
        {"step":0,"attempt":0,"model":"other","model_source":"request","total_tokens":5}}]}}'
        WHERE role='assistant'"#,
        )
        .unwrap();
        let mut args = arguments();
        args["group_by"] = json!("model");
        args["limit"] = json!(1);
        let first = query_usage(conn, &args, &["1".into()]).unwrap();
        assert_eq!(first["rows"][0]["key"], "request:fixture-model");
        assert_eq!(first["rows"][0]["assistant_messages"], 1);
        assert_eq!(first["rows"][0]["observations"], 0);
        args["cursor"] = first["next_cursor"].clone();
        let second = query_usage(conn, &args, &["1".into()]).unwrap();
        assert_eq!(second["rows"][0]["key"], "request:other");
        assert_eq!(second["rows"][0]["assistant_messages"], 0);
        assert_eq!(second["rows"][0]["tokens"], json!([null, null, 5]));
        args["cursor"] = second["next_cursor"].clone();
        let third = query_usage(conn, &args, &["1".into()]).unwrap();
        assert_eq!(third["rows"][0]["key"], "unknown");
        assert_eq!(third["rows"][0]["human_messages"], 1);
        assert!(third["next_cursor"].is_null());
        for page in [&first, &second, &third] {
            assert!(serde_json::to_vec(page).unwrap().len() <= 1200);
            assert_eq!(page["cost"], "unavailable:no_versioned_prices");
        }
        args["timezone"] = json!("UTC");
        assert!(
            query_usage(conn, &args, &["1".into()]).is_err(),
            "cursor binds filters"
        );
    });
}

#[test]
fn malformed_and_conflicting_observations_are_reported_without_fabricated_tokens() {
    with_database(|conn| {
        conn.batch_execute(r#"UPDATE messages SET tool_results='{"conversation_trace":{"trace_deltas":[
            {"kind":"timing","title":"Model usage","metadata":{"step":0,"attempt":0,"total_tokens":12}},
            {"kind":"timing","title":"Model usage","metadata":{"step":0,"attempt":0,"total_tokens":99}},
            {"kind":"timing","title":"Model usage","metadata":{"total_tokens":55}},
            {"kind":"timing","title":"Model usage","metadata":{"step":0,"attempt":1,"total_tokens":-5,"prompt_tokens":"10","completion_tokens":1.5}}
        ]}}' WHERE role='assistant'"#).unwrap();
        let result = query_usage(conn, &arguments(), &["1".into()]).unwrap();
        let row = &result["rows"][0];
        assert_eq!(row["tokens"], json!([null, null, null]));
        assert_eq!(row["assistant_with_usage"], 0);
        assert_eq!(row["observations"], 2);
        assert_eq!(row["conflicts"], 1);
        assert_eq!(row["invalid_observations"], 1);
    });
}

#[test]
fn user_pages_only_count_joined_current_owned_human_and_assistant_records() {
    with_database(|conn| {
        conn.batch_execute("INSERT INTO web_sessions VALUES
        ('00000000-0000-0000-0000-000000000002','00000000-0000-0000-0000-000000000012','admin','1'),
        ('00000000-0000-0000-0000-000000000003','00000000-0000-0000-0000-000000000013','user','2'),
        ('00000000-0000-0000-0000-000000000004','00000000-0000-0000-0000-000000000014','user','3');
        INSERT INTO messages VALUES
        ('00000000-0000-0000-0000-000000000104','00000000-0000-0000-0000-000000000012','admin:1','assistant','2026-03-08T07:00:00Z',NULL),
        ('00000000-0000-0000-0000-000000000105','00000000-0000-0000-0000-000000000013','user:2','user','2026-03-08T07:00:00Z',NULL),
        ('00000000-0000-0000-0000-000000000106','00000000-0000-0000-0000-000000000014','user:3','user','2026-03-08T07:00:00Z',NULL),
        ('00000000-0000-0000-0000-000000000107','00000000-0000-0000-0000-000000000011','user:1','system','2026-03-08T07:00:00Z',NULL),
        ('00000000-0000-0000-0000-000000000108','00000000-0000-0000-0000-000000000011','user:other','user','2026-03-08T07:00:00Z',NULL),
        ('00000000-0000-0000-0000-000000000109','00000000-0000-0000-0000-000000000099','user:1','user','2026-03-08T07:00:00Z',NULL);").unwrap();
        let mut args = arguments();
        args["group_by"] = json!("user");
        let first = query_usage(conn, &args, &["1".into(), "2".into()]).unwrap();
        assert_eq!(first["rows"][0]["key"], "1");
        assert_eq!(first["rows"][0]["human_messages"], 1);
        args["cursor"] = first["next_cursor"].clone();
        let second = query_usage(conn, &args, &["1".into(), "2".into()]).unwrap();
        assert_eq!(second["rows"][0]["key"], "2");
        assert_eq!(second["rows"][0]["human_messages"], 1);
        assert!(second["next_cursor"].is_null());
    });
}

#[test]
fn invalid_timezones_dates_intervals_and_page_arguments_are_rejected() {
    with_database(|conn| {
        for (field, value) in [
            ("timezone", json!("Mars/Olympus")),
            ("start", json!("2026-03-08T06:00:00")),
            ("end", json!("2026-03-08T06:00:00Z")),
            ("limit", json!(0)),
            ("limit", json!(11)),
            ("group_by", json!("sql")),
            ("include_admin_tests", json!("true")),
            ("cursor", json!("garbage")),
        ] {
            let mut args = arguments();
            args[field] = value;
            assert!(query_usage(conn, &args, &["1".into()]).is_err(), "{field}");
        }
    });
}

fn actor(kind: &str, approved: bool) -> InternalAuthContext {
    serde_json::from_value(
        json!({"id":1,"type":kind,"approved":approved,"pubkey":"a".repeat(64),
        "email":null,"name":null,"user_type_id":null,"dev_mode":false}),
    )
    .unwrap()
}

fn tool_arguments(value: Value) -> ToolArgs {
    let mut args = ToolArgs::new();
    for (key, value) in value.as_object().unwrap() {
        args.insert(key.clone(), value.clone());
    }
    args
}

fn backend(status: &str, body: Value) -> (InternalAgentClient, std::thread::JoinHandle<String>) {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let status = status.to_owned();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let mut bytes = Vec::new();
        let mut buffer = [0; 4096];
        loop {
            let n = stream.read(&mut buffer).unwrap();
            assert!(n > 0);
            bytes.extend_from_slice(&buffer[..n]);
            if let Some(end) = bytes.windows(4).position(|v| v == b"\r\n\r\n") {
                let headers = String::from_utf8_lossy(&bytes[..end]);
                let length = headers
                    .lines()
                    .find_map(|line| {
                        line.to_lowercase()
                            .strip_prefix("content-length:")
                            .map(|v| v.trim().parse::<usize>().unwrap())
                    })
                    .unwrap_or(0);
                if bytes.len() >= end + 4 + length {
                    break;
                }
            }
        }
        let body = body.to_string();
        write!(stream,"HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).unwrap();
        String::from_utf8(bytes).unwrap()
    });
    (
        InternalAgentClient {
            http: reqwest::Client::new(),
            backend_url: format!("http://{address}"),
            internal_agent_token: "usage-fixture".into(),
        },
        handle,
    )
}

#[test]
fn execution_rechecks_admin_database_and_live_provenance() {
    let Some(conn) = fixture_connection() else {
        return;
    };
    let db = Arc::new(Mutex::new(conn));
    let runtime = tokio::runtime::Runtime::new().unwrap();
    for (kind, approved, enabled) in [
        ("user", true, true),
        ("impersonation", true, true),
        ("admin", false, true),
        ("admin", true, false),
    ] {
        let tool = UsageTool {
            db: db.clone(),
            internal: InternalAgentClient {
                http: reqwest::Client::new(),
                backend_url: "http://127.0.0.1:1".into(),
                internal_agent_token: String::new(),
            },
            auth: actor(kind, approved),
            database_enabled: enabled,
        };
        let result = runtime
            .block_on(tool.execute_native(&tool_arguments(arguments())))
            .unwrap();
        assert!(matches!(result,NativeToolResult::Failure{ref code,..} if code=="forbidden"));
    }
    let (internal, handle) = backend("403 Forbidden", json!({"detail":"Admin no longer exists"}));
    let tool = UsageTool {
        db,
        internal,
        auth: actor("admin", true),
        database_enabled: true,
    };
    let result = runtime
        .block_on(tool.execute_native(&tool_arguments(arguments())))
        .unwrap();
    assert!(matches!(result, NativeToolResult::Failure { .. }));
    assert!(handle
        .join()
        .unwrap()
        .starts_with("POST /internal/agent/admin/usage-users "));
}

#[test]
fn execution_excludes_admin_tests_and_deleted_users_by_live_classifier() {
    let Some(mut conn) = fixture_connection() else {
        return;
    };
    conn.batch_execute("INSERT INTO web_sessions VALUES
    ('00000000-0000-0000-0000-000000000003','00000000-0000-0000-0000-000000000013','user','2'),
    ('00000000-0000-0000-0000-000000000004','00000000-0000-0000-0000-000000000014','user','3');
    INSERT INTO messages VALUES
    ('00000000-0000-0000-0000-000000000105','00000000-0000-0000-0000-000000000013','user:2','user','2026-03-08T07:00:00Z',NULL),
    ('00000000-0000-0000-0000-000000000106','00000000-0000-0000-0000-000000000014','user:3','user','2026-03-08T07:00:00Z',NULL);").unwrap();
    let db = Arc::new(Mutex::new(conn));
    let runtime = tokio::runtime::Runtime::new().unwrap();
    for include in [false, true] {
        let (internal, handle) = backend(
            "200 OK",
            json!({"users":[{"id":1,"is_test":false},{"id":2,"is_test":true}]}),
        );
        let tool = UsageTool {
            db: db.clone(),
            internal,
            auth: actor("admin", true),
            database_enabled: true,
        };
        let mut args = arguments();
        args["include_admin_tests"] = json!(include);
        let NativeToolResult::Success(result) = runtime
            .block_on(tool.execute_native(&tool_arguments(args)))
            .unwrap()
        else {
            panic!("usage read failed")
        };
        assert_eq!(
            result["rows"][0]["human_messages"],
            if include { 2 } else { 1 }
        );
        assert_eq!(result["rows"][0]["assistant_messages"], 1);
        let request = handle.join().unwrap();
        assert!(request.contains("x-internal-agent-token: usage-fixture"));
        let body: Value = serde_json::from_str(request.split_once("\r\n\r\n").unwrap().1).unwrap();
        assert_eq!(body["user_ids"], json!([1, 2, 3]));
    }
}

#[test]
fn empty_data_still_requires_live_admin_and_foreign_or_duplicate_owners_fail_closed() {
    let Some(conn) = fixture_connection() else {
        return;
    };
    let db = Arc::new(Mutex::new(conn));
    let runtime = tokio::runtime::Runtime::new().unwrap();
    for body in [
        json!({"users":[{"id":2,"is_test":false}]}),
        json!({"users":[{"id":1,"is_test":false},{"id":1,"is_test":false}]}),
    ] {
        let (internal, handle) = backend("200 OK", body);
        let tool = UsageTool {
            db: db.clone(),
            internal,
            auth: actor("admin", true),
            database_enabled: true,
        };
        assert!(matches!(
            runtime
                .block_on(tool.execute_native(&tool_arguments(arguments())))
                .unwrap(),
            NativeToolResult::Failure { .. }
        ));
        handle.join().unwrap();
    }
    let (internal, handle) = backend("403 Forbidden", json!({"detail":"revoked"}));
    let tool = UsageTool {
        db,
        internal,
        auth: actor("admin", true),
        database_enabled: true,
    };
    let mut args = arguments();
    args["start"] = json!("2027-01-01T00:00:00Z");
    args["end"] = json!("2027-01-02T00:00:00Z");
    assert!(matches!(
        runtime
            .block_on(tool.execute_native(&tool_arguments(args)))
            .unwrap(),
        NativeToolResult::Failure { .. }
    ));
    let request = handle.join().unwrap();
    let body: Value = serde_json::from_str(request.split_once("\r\n\r\n").unwrap().1).unwrap();
    assert_eq!(body["user_ids"], json!([]));
}

#[test]
fn byte_budget_paginates_complete_rows_without_losing_groups() {
    with_database(|conn| {
        conn.batch_execute(
            "INSERT INTO messages SELECT md5(n::text)::uuid,
        '00000000-0000-0000-0000-000000000011'::uuid,'user:1','user',
        '2026-03-10T12:00:00Z'::timestamptz+n*interval '1 day',NULL FROM generate_series(1,12) n;",
        )
        .unwrap();
        let mut args = arguments();
        args["end"] = json!("2026-04-01T00:00:00Z");
        args["limit"] = json!(10);
        let mut keys = Vec::new();
        for _ in 0..20 {
            let result = query_usage(conn, &args, &["1".into()]).unwrap();
            assert!(serde_json::to_vec(&result).unwrap().len() <= 1200);
            for row in result["rows"].as_array().unwrap() {
                keys.push(row["key"].as_str().unwrap().to_string());
            }
            if result["next_cursor"].is_null() {
                break;
            }
            args["cursor"] = result["next_cursor"].clone();
        }
        assert_eq!(keys.len(), 14);
        assert_eq!(keys.first().unwrap(), "2026-03-08");
        assert_eq!(keys.last().unwrap(), "2026-03-22");
        assert!(keys.windows(2).all(|pair| pair[0] < pair[1]));
    });
}

#[test]
fn shared_agent_sessions_do_not_multiply_messages_or_observations() {
    with_database(|conn| {
        conn.batch_execute(r#"INSERT INTO web_sessions VALUES
        ('00000000-0000-0000-0000-000000000002','00000000-0000-0000-0000-000000000011','user','1');
        UPDATE messages SET tool_results='{"conversation_trace":{"trace_deltas":[
        {"kind":"timing","title":"Model usage","metadata":{"step":0,"attempt":0,"total_tokens":5}}]}}'
        WHERE role='assistant';"#).unwrap();
        let result = query_usage(conn, &arguments(), &["1".into()]).unwrap();
        let row = &result["rows"][0];
        assert_eq!(row["human_messages"], 1);
        assert_eq!(row["assistant_messages"], 1);
        assert_eq!(row["active_conversations"], 2);
        assert_eq!(row["observations"], 1);
        assert_eq!(row["duplicates"], 0);
        assert_eq!(row["tokens"], json!([null, null, 5]));
    });
}

#[test]
fn user_rankings_page_by_descending_message_count_then_numeric_id_without_skipped_ties() {
    with_database(|conn| {
        conn.batch_execute("INSERT INTO web_sessions SELECT md5('session'||n)::uuid,md5('agent'||n)::uuid,'user',n::text
        FROM generate_series(2,7) n;
        INSERT INTO messages SELECT md5('message'||n||':'||j)::uuid,md5('agent'||n)::uuid,'user:'||n,'user',
        '2026-03-08T12:00:00Z'::timestamptz,NULL FROM generate_series(2,7) n
        CROSS JOIN LATERAL generate_series(1,CASE n WHEN 2 THEN 9 WHEN 3 THEN 5 WHEN 4 THEN 5 WHEN 5 THEN 8 WHEN 6 THEN 1 ELSE 5 END) j;").unwrap();
        let owners = (1..=7).map(|n| n.to_string()).collect::<Vec<_>>();
        let mut args = arguments();
        args["group_by"] = json!("user");
        let mut ranked = Vec::new();
        for _ in 0..8 {
            let page = query_usage(conn, &args, &owners).unwrap();
            assert_eq!(page["order"], "messages_desc,user_id_asc");
            let row = &page["rows"][0];
            ranked.push((
                row["key"].as_str().unwrap().to_string(),
                row["human_messages"].as_i64().unwrap()
                    + row["assistant_messages"].as_i64().unwrap(),
            ));
            if page["next_cursor"].is_null() {
                break;
            }
            args["cursor"] = page["next_cursor"].clone();
        }
        assert_eq!(
            ranked,
            vec![
                ("2".into(), 9),
                ("5".into(), 8),
                ("3".into(), 5),
                ("4".into(), 5),
                ("7".into(), 5),
                ("1".into(), 2),
                ("6".into(), 1)
            ]
        );
    });
}

#[test]
fn slow_query_is_cancelled_and_does_not_leak_timeout_or_abort_caller_transaction() {
    with_database(|conn| {
        conn.batch_execute(
            "SET LOCAL statement_timeout=0;
            ALTER TABLE messages RENAME TO usage_fixture_messages;
            CREATE TEMP VIEW messages AS SELECT m.* FROM usage_fixture_messages m
            CROSS JOIN (SELECT pg_sleep(6)) slow;",
        )
        .unwrap();
        let started = std::time::Instant::now();
        let result = query_usage(conn, &arguments(), &["1".into()]);
        assert!(
            result.is_err(),
            "broad query must be cancelled before its six-second scan finishes"
        );
        assert!(started.elapsed() < std::time::Duration::from_secs(6));
        #[derive(diesel::QueryableByName)]
        struct Setting {
            #[diesel(sql_type=diesel::sql_types::Text)]
            value: String,
        }
        let setting = diesel::sql_query("SELECT current_setting('statement_timeout') AS value")
            .get_result::<Setting>(conn)
            .unwrap();
        assert_eq!(setting.value, "0");

        conn.batch_execute("SET LOCAL statement_timeout=50")
            .unwrap();
        let started = std::time::Instant::now();
        assert!(query_usage(conn, &arguments(), &["1".into()]).is_err());
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
        let setting = diesel::sql_query("SELECT current_setting('statement_timeout') AS value")
            .get_result::<Setting>(conn)
            .unwrap();
        assert_eq!(setting.value, "50ms");
    });
}

#[test]
fn busy_shared_database_connection_fails_promptly_without_waiting_after_tool_cancellation() {
    let Some(conn) = fixture_connection() else {
        return;
    };
    let db = Arc::new(Mutex::new(conn));
    let guard = db.lock().unwrap();
    let tool = UsageTool {
        db: db.clone(),
        internal: InternalAgentClient {
            http: reqwest::Client::new(),
            backend_url: "http://127.0.0.1:1".into(),
            internal_agent_token: String::new(),
        },
        auth: actor("admin", true),
        database_enabled: true,
    };
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let started = std::time::Instant::now();
    let result = runtime
        .block_on(tool.execute_native(&tool_arguments(arguments())))
        .unwrap();
    assert!(matches!(result, NativeToolResult::Failure { .. }));
    assert!(started.elapsed() < std::time::Duration::from_secs(2));
    drop(guard);
}
