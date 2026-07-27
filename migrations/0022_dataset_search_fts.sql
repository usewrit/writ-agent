-- 0022_dataset_search_fts.sql
-- Full-text search over a dataset's records, backing writ_dataset_search and the
-- /v1/datasets/search[/:id] routes. A dataset's records are the extracted_data
-- JSON of its runs; we index that text in an FTS5 table so a search finds the
-- matching runs FAST and COMPLETELY (no in-memory scan cap). The handler then
-- flattens only those matched runs and keeps the records that contain every term
-- — so the index is a candidate-finder and relevance/highlight stay in the
-- shared flatten layer (identical behaviour to the cloud Postgres path).
--
-- Each FTS row mirrors a `runs` row (rowid = runs.id); `body` is the run's
-- extracted_data as text (json_extract → the sub-JSON, NULL rows are skipped).
-- Triggers keep it in lockstep with every runs write; existing runs are
-- backfilled on create. FTS5 + JSON1 are compiled into the bundled SQLCipher
-- amalgamation (verified by the db::open migrate test).

CREATE VIRTUAL TABLE run_data_fts USING fts5(
    body,
    workflow_id UNINDEXED,
    run_id UNINDEXED,
    tokenize = 'unicode61'
);

-- EVERY json_extract below is guarded by json_valid FIRST. `json_extract` RAISES
-- ("malformed JSON") on a non-JSON argument rather than returning NULL, and these
-- run inside triggers on `runs` — so an unguarded extract would make a malformed
-- result_data blob abort the write that carries it, i.e. a run could not be
-- COMPLETED, and the backfill below would abort this whole migration (bricking the
-- upgrade) if any single pre-existing row held non-JSON. json_valid() never raises,
-- and SQL AND short-circuits, so a bad blob is simply skipped from the index
-- instead of breaking the run that owns it. Indexing is best-effort; run
-- correctness is not.

-- Backfill runs that already carry extracted_data.
INSERT INTO run_data_fts(rowid, body, workflow_id, run_id)
SELECT id, json_extract(result_data, '$.extracted_data'), workflow_id, id
FROM runs
WHERE json_valid(result_data)
  AND json_extract(result_data, '$.extracted_data') IS NOT NULL;

-- A run is created 'running' with NULL result_data, then completion UPDATEs
-- result_data — so the UPDATE trigger does the real indexing; the INSERT trigger
-- covers the rare case of a run written already-populated. Empty/NULL
-- extracted_data is never indexed (matches nothing, keeps the table lean).
CREATE TRIGGER runs_fts_ai AFTER INSERT ON runs
WHEN json_valid(NEW.result_data)
 AND json_extract(NEW.result_data, '$.extracted_data') IS NOT NULL
BEGIN
    INSERT INTO run_data_fts(rowid, body, workflow_id, run_id)
    VALUES (NEW.id, json_extract(NEW.result_data, '$.extracted_data'), NEW.workflow_id, NEW.id);
END;

CREATE TRIGGER runs_fts_ad AFTER DELETE ON runs BEGIN
    DELETE FROM run_data_fts WHERE rowid = OLD.id;
END;

CREATE TRIGGER runs_fts_au AFTER UPDATE OF result_data ON runs BEGIN
    DELETE FROM run_data_fts WHERE rowid = OLD.id;
    INSERT INTO run_data_fts(rowid, body, workflow_id, run_id)
    SELECT NEW.id, json_extract(NEW.result_data, '$.extracted_data'), NEW.workflow_id, NEW.id
    WHERE json_valid(NEW.result_data)
      AND json_extract(NEW.result_data, '$.extracted_data') IS NOT NULL;
END;
