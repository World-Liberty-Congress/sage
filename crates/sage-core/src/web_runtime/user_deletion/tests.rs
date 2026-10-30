use super::*;
use diesel::connection::SimpleConnection;

#[test]
fn active_turns_block_deletion_and_mark_blocks_late_admission() {
    let owners = OwnerActivity::default();
    let user_turn = owners.admit("user", "42").unwrap();
    // Admin continuations use the stored owner and take the same admission.
    let admin_turn = owners.admit("user", "42").unwrap();
    assert_eq!(
        owners.exclusive("user", "42", true).unwrap_err().status,
        StatusCode::CONFLICT
    );
    assert!(owners.admit("user", "42").is_err());
    assert!(owners.admit("user", "43").is_ok());
    assert!(owners.admit("admin", "42").is_ok());
    drop(user_turn);
    assert!(owners.exclusive("user", "42", true).is_err());
    drop(admin_turn);
    assert!(owners.exclusive("user", "42", true).is_ok());
    assert!(owners.admit("user", "42").is_err());
}

#[tokio::test]
async fn stream_keeps_admission_until_body_is_dropped() {
    use futures_util::StreamExt;
    let owners = OwnerActivity::default();
    let activity = owners.admit("user", "42").unwrap();
    let stream = async_stream::stream! {
        let _activity = activity;
        yield 1;
        std::future::pending::<()>().await;
    };
    let mut stream = Box::pin(stream);
    assert!(owners.exclusive("user", "42", false).is_err());
    assert_eq!(stream.next().await, Some(1));
    assert!(owners.exclusive("user", "42", false).is_err());
    drop(stream);
    assert!(owners.exclusive("user", "42", false).is_ok());
}

#[test]
fn conversation_deletion_excludes_turns_without_revoking_user() {
    let owners = OwnerActivity::default();
    let turn = owners.admit("user", "42").unwrap();
    assert!(owners.exclusive("user", "42", false).is_err());
    drop(turn);
    let deletion = owners.exclusive("user", "42", false).unwrap();
    assert!(owners.admit("user", "42").is_err());
    drop(deletion);
    assert!(owners.admit("user", "42").is_ok());
}

#[tokio::test]
#[ignore = "requires an isolated synthetic USER_DELETION_TEST_DATABASE_URL"]
async fn postgres_purge_is_atomic_scoped_idempotent_and_covers_identity_only() {
    use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};
    const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations");
    let url = std::env::var("USER_DELETION_TEST_DATABASE_URL").unwrap();
    let mut conn = PgConnection::establish(&url).unwrap();
    conn.run_pending_migrations(MIGRATIONS).unwrap();
    conn.begin_test_transaction().unwrap();
    let owner = Uuid::new_v4().to_string();
    let other = Uuid::new_v4().to_string();
    let identity_only = Uuid::new_v4().to_string();
    let ids: Vec<_> = (0..4).map(|_| Uuid::new_v4()).collect();
    for (index, agent) in ids.iter().enumerate() {
        let kind = if index == 3 { "admin" } else { "user" };
        let id = if index == 2 { &other } else { &owner };
        conn.batch_execute(&format!(
            r#"
          INSERT INTO agents (id, name, system_prompt) VALUES ('{agent}','fixture','fixture');
          INSERT INTO web_sessions (id,agent_id,owner_type,owner_id)
            VALUES (gen_random_uuid(),'{agent}','{kind}','{id}');
          INSERT INTO messages (id,agent_id,user_id,role,content)
            VALUES (gen_random_uuid(),'{agent}','admin:99','assistant','synthetic');
          INSERT INTO blocks (agent_id,label,value) VALUES ('{agent}','human','synthetic');
          INSERT INTO passages (agent_id,content) VALUES ('{agent}','synthetic');
          INSERT INTO summaries (agent_id,from_sequence_id,to_sequence_id,content)
            VALUES ('{agent}',1,1,'synthetic');
          INSERT INTO user_preferences (agent_id,key,value) VALUES ('{agent}','test','synthetic');
          INSERT INTO scheduled_tasks (agent_id,task_type,payload,next_run_at,description)
            VALUES ('{agent}','message','{{}}',NOW(),'fixture');
        "#
        ))
        .unwrap();
    }
    for (kind, id) in [
        ("user", &owner),
        ("user", &other),
        ("admin", &owner),
        ("user", &identity_only),
    ] {
        diesel::sql_query("INSERT INTO external_identities (id,identity_type,external_id,display_name) VALUES (gen_random_uuid(),$1,$2,'synthetic')")
            .bind::<Varchar,_>(kind).bind::<Varchar,_>(id).execute(&mut conn).unwrap();
    }
    // Fail after memory/session deletes: all earlier writes must roll back.
    conn.batch_execute("CREATE FUNCTION pg_temp.reject_identity_delete() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected'; END $$;
        CREATE TRIGGER reject_cleanup BEFORE DELETE ON external_identities FOR EACH ROW EXECUTE FUNCTION pg_temp.reject_identity_delete();").unwrap();
    assert!(purge_user(&mut conn, &owner).is_err());
    for agent in &ids {
        assert_eq!(
            messages::table
                .filter(messages::agent_id.eq(agent))
                .count()
                .get_result::<i64>(&mut conn)
                .unwrap(),
            1
        );
        assert_eq!(
            web_sessions::table
                .filter(web_sessions::agent_id.eq(agent))
                .count()
                .get_result::<i64>(&mut conn)
                .unwrap(),
            1
        );
    }
    conn.batch_execute("DROP TRIGGER reject_cleanup ON external_identities")
        .unwrap();
    assert_eq!(purge_user(&mut conn, &owner).unwrap(), (2, 1));
    for (index, agent) in ids.iter().enumerate() {
        let expected = if index < 2 { 0 } else { 1 };
        for table in [
            "agents",
            "messages",
            "summaries",
            "blocks",
            "passages",
            "user_preferences",
            "scheduled_tasks",
            "web_sessions",
        ] {
            let column = if table == "agents" { "id" } else { "agent_id" };
            #[derive(QueryableByName)]
            struct Count {
                #[diesel(sql_type=diesel::sql_types::BigInt)]
                n: i64,
            }
            let count = diesel::sql_query(format!(
                "SELECT COUNT(*) AS n FROM {table} WHERE {column}::text='{agent}'"
            ))
            .get_result::<Count>(&mut conn)
            .unwrap();
            assert_eq!(count.n, expected, "{table}, agent {index}");
        }
    }
    assert_eq!(purge_user(&mut conn, &owner).unwrap(), (0, 0));
    assert_eq!(purge_user(&mut conn, &identity_only).unwrap(), (0, 1));
    // Exercise the real admission/session helper and private route together.
    let mut config = Config::from_env().unwrap();
    config.database_url = url;
    let http = Client::new();
    let state = WebAppState {
        config,
        http: http.clone(),
        db: Arc::new(Mutex::new(conn)),
        web_config: EnclaveWebConfig {
            http_port: 0,
            backend_url: "http://127.0.0.1:1".into(),
            internal_agent_token: "synthetic-token".into(),
            secret_key: "synthetic".into(),
            allowed_origins: vec![],
            frontend_url: None,
            user_session_cookie_name: "user".into(),
            admin_session_cookie_name: "admin".into(),
            csrf_cookie_name: "csrf".into(),
        },
        internal: InternalAgentClient::new(
            http,
            "http://127.0.0.1:1".into(),
            "synthetic-token".into(),
        ),
        owner_activity: Arc::default(),
        user_lookups: Arc::default(),
    };
    let stale_auth: InternalAuthContext = serde_json::from_value(json!({
        "id": 701, "type": "user", "approved": true, "dev_mode": false,
    }))
    .unwrap();
    let (session, turn) = get_or_create_web_session(&state, None, &stale_auth).unwrap();
    let mut headers = HeaderMap::new();
    headers.insert(
        "X-Internal-Agent-Token",
        HeaderValue::from_static("synthetic-token"),
    );
    assert_eq!(
        delete_user_runtime(State(state.clone()), HeaderMap::new(), Path(701))
            .await
            .unwrap_err()
            .status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        delete_user_runtime(State(state.clone()), headers.clone(), Path(701))
            .await
            .unwrap_err()
            .status,
        StatusCode::CONFLICT
    );
    // A request authenticated before deletion is stopped before creating memory.
    assert_eq!(
        get_or_create_web_session(&state, None, &stale_auth)
            .unwrap_err()
            .status,
        StatusCode::GONE
    );
    let admin_auth: InternalAuthContext = serde_json::from_value(json!({
        "id": 99, "type": "admin", "approved": true, "dev_mode": false,
    }))
    .unwrap();
    assert!(get_or_create_web_session(&state, Some(&session.id.to_string()), &admin_auth).is_err());
    drop(turn);
    let result = delete_user_runtime(State(state.clone()), headers.clone(), Path(701))
        .await
        .unwrap()
        .0;
    assert_eq!(result["conversations_deleted"], 1);
    assert_eq!(result["deletion"]["status"], "succeeded");
    assert!(get_or_create_web_session(&state, None, &stale_auth).is_err());
    assert_eq!(
        delete_user_runtime(State(state.clone()), headers, Path(701))
            .await
            .unwrap()
            .0["conversations_deleted"],
        0
    );
    // Deterministically pause a Conversation DELETE at its authorized snapshot,
    // purge the User, then recreate that UUID under Admin ownership.
    let (replacement, admin_turn) =
        get_or_create_web_session(&state, Some(&session.id.to_string()), &admin_auth).unwrap();
    let _stale_delete = state
        .owner_activity
        .exclusive("user", "701", false)
        .unwrap();
    let mut conn = state.db.lock().unwrap();
    conn.batch_execute(&format!(
        "INSERT INTO agents(id,name,system_prompt) VALUES ('{}','fixture','fixture');
         INSERT INTO messages(agent_id,user_id,role,content) VALUES ('{}','admin:99','assistant','synthetic');",
        replacement.agent_id, replacement.agent_id,
    )).unwrap();
    for remove_session in [true, false] {
        assert_eq!(
            delete_session_state(&mut conn, &session, remove_session)
                .unwrap_err()
                .status,
            StatusCode::CONFLICT
        );
        assert_eq!(
            web_sessions::table
                .find(replacement.id)
                .count()
                .get_result::<i64>(&mut *conn)
                .unwrap(),
            1
        );
        assert_eq!(
            messages::table
                .filter(messages::agent_id.eq(replacement.agent_id))
                .count()
                .get_result::<i64>(&mut *conn)
                .unwrap(),
            1
        );
    }
    drop(admin_turn);
    let _admin_delete = state
        .owner_activity
        .exclusive("admin", "99", false)
        .unwrap();
    assert!(delete_session_state(&mut conn, &replacement, true)
        .unwrap()
        .is_some());
    assert!(delete_session_state(&mut conn, &replacement, true)
        .unwrap()
        .is_none());
}
