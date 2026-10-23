-- When Sage next retries the Admin review record of a User Conversation that
-- the backend has not confirmed. NULL when the record is up to date.
ALTER TABLE web_sessions
    ADD COLUMN IF NOT EXISTS session_log_retry_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_web_sessions_session_log_retry_at
    ON web_sessions (session_log_retry_at)
    WHERE session_log_retry_at IS NOT NULL;
