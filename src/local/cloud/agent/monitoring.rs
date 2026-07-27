//! `assign_targets` / `target_sync` / `assign_workflows` — cloud monitoring/workflow assignment frames.
//!
//! A user-hosted DESKTOP is a BYO execution agent for the OWNER's own work — it is NOT a node in the
//! shared monitoring-distribution fleet. The cloud's `assign_targets` distributes monitor TARGETS from
//! the shared fleet (potentially OTHER tenants' targets) across fleet agents; persisting those into the
//! desktop's local `targets` store would (a) surface FOREIGN monitors the user never created and (b)
//! make the local scheduler actually CHECK them on the user's machine. That is wrong on both privacy
//! and correctness grounds.
//!
//! So these frames are ACK-ONLY here: NOTHING is ever written to the local store. The desktop runs ONLY
//! the user's OWN local monitors (created locally, or explicitly synced from the cloud). The agent also
//! no longer advertises the `monitoring` capability in its connect body, so the backend should not send
//! these at all — this handler is the defense-in-depth second line if one still arrives.
//!
//! SECURITY (the never-trust-a-BYO-agent rule): identity/billing stay server-side; a non-panicking ack
//! that persists nothing can leak nothing and can never run a foreign tenant's check on this device.

use serde_json::{json, Value};

/// Handle `assign_targets` / `target_sync`: ACK WITHOUT PERSISTING. The desktop never adopts cloud-
/// pushed monitor targets (see module docs) — it runs only the user's own local monitors. Returns the
/// ack frame for the router to send. Never touches the local store; never panics.
pub fn handle_assign_targets(msg: &Value) -> Value {
    let assignment_id = msg["assignment_id"].as_str().unwrap_or("").to_string();
    let count = msg
        .get("targets")
        .and_then(Value::as_array)
        .map(|a| a.len())
        .unwrap_or(0);
    tracing::info!(
        assignment_id,
        count,
        "assign_targets IGNORED on a user-hosted BYO agent (runs only its own local monitors; nothing persisted)"
    );
    json!({
        "type": "targets_assigned",
        "assignment_id": assignment_id,
        // Honest: the agent does NOT accept shared-fleet monitor assignment.
        "success": false,
        "inserted": 0,
        "updated": 0,
        "skipped": count,
        "error": "monitor assignment is not accepted on a user-hosted agent (it runs only your own local monitors)",
    })
}

/// Handle `assign_workflows`: ACK accepted-but-not-persisted (the workflows still run cloud-side). The
/// desktop has no cloud→local workflow id map and never adopts pushed assignments. Non-panicking.
pub fn handle_assign_workflows(msg: &Value) -> Value {
    let assignment_id = msg["assignment_id"].as_str().unwrap_or("").to_string();
    let count = msg
        .get("workflows")
        .and_then(Value::as_array)
        .map(|a| a.len())
        .unwrap_or(0);
    tracing::info!(
        assignment_id,
        count,
        "assign_workflows acknowledged (not persisted on this agent)"
    );
    json!({
        "type": "workflows_assigned",
        "assignment_id": assignment_id,
        "success": false,
        "accepted": count,
        "persisted": 0,
        "error": "workflow assignment is not persisted on this agent",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assign_targets_acks_without_persisting() {
        // Even a well-formed assignment is REFUSED (not persisted) — the desktop never adopts foreign
        // monitor targets. The ack reports the count as skipped and success:false.
        let frame = json!({
            "type": "assign_targets",
            "assignment_id": "asg-1",
            "targets": [
                {"url": "https://a.example.com", "check_type": "content"},
                {"url": "https://b.example.com", "check_type": "uptime"}
            ]
        });
        let ack = handle_assign_targets(&frame);
        assert_eq!(ack["type"], "targets_assigned");
        assert_eq!(ack["assignment_id"], "asg-1");
        assert_eq!(ack["success"], false, "user-hosted agent does not adopt shared-fleet monitors");
        assert_eq!(ack["inserted"], 0);
        assert_eq!(ack["updated"], 0);
        assert_eq!(ack["skipped"], 2);
        assert!(ack["error"].as_str().unwrap().contains("your own local monitors"));
    }

    #[test]
    fn assign_targets_empty_list_is_a_clean_ack() {
        let ack = handle_assign_targets(&json!({"assignment_id": "asg-empty"}));
        assert_eq!(ack["type"], "targets_assigned");
        assert_eq!(ack["skipped"], 0);
        assert_eq!(ack["inserted"], 0);
    }

    #[test]
    fn assign_workflows_acks_not_persisted() {
        let ack = handle_assign_workflows(&json!({
            "assignment_id": "wf-asg",
            "workflows": [{"id": 1}, {"id": 2}]
        }));
        assert_eq!(ack["type"], "workflows_assigned");
        assert_eq!(ack["success"], false, "honestly not persisted on this agent");
        assert_eq!(ack["accepted"], 2);
        assert_eq!(ack["persisted"], 0);
    }
}
