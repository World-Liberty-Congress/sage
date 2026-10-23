DROP INDEX IF EXISTS idx_web_sessions_session_log_retry_at;

ALTER TABLE web_sessions
    DROP COLUMN IF EXISTS session_log_retry_at;
