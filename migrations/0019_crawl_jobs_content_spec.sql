-- Configurable content-selection spec for a LOCAL crawl:
-- {preset, include_comments, exclude_selectors, include_selectors, keep}. JSON-TEXT;
-- NULL = the engine's default extraction. Mirrors the cloud crawl_jobs.content_spec
-- (backend migration 0094) so a self-host crawl honors the same content selection the
-- fleet does, and a linked desktop can forward it to the cloud.
ALTER TABLE crawl_jobs ADD COLUMN content_spec TEXT;
