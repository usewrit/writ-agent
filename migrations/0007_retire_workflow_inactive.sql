-- Retire the workflow "deactivate"/soft-delete state. A workflow is now either present or hard-
-- deleted (DELETE removes the row + cascades its runs) — it can never be parked `is_active = 0`.
-- Reactivate every workflow left inactive by the old soft-delete so it returns to the Workflows list
-- alongside its extracted data; the user removes the ones they don't want with a real delete. The
-- column survives (still written by create) but is no longer a user-toggleable lifecycle state.
UPDATE workflows SET is_active = 1 WHERE is_active = 0;
