-- CONCIERGE LIVE BROWSER PREVIEW — persist the latest screenshot + current URL of the page the AI
-- concierge is on, so the FE "Preview" button (GET /v1/ai-concierge/{id}/preview) can show what the
-- mission is looking at while it browses. `live_screenshot` is a base64 JPEG (no data: prefix, the FE
-- adds it); `current_url` is the page URL captured alongside it. Both nullable (null until the first
-- frame). Mirrors the cloud concierge_session preview columns.
ALTER TABLE concierge_sessions ADD COLUMN live_screenshot TEXT;
ALTER TABLE concierge_sessions ADD COLUMN current_url TEXT;
