//! Durable authority for one native descendant-deferred goal boundary.
//! This is not a scan of active goals and never replays a factory or child task.
use pa_types::goal::{GoalState, GoalStatus};
use pa_types::session::{CustomMessage, FileEntry};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::Path;

pub(crate) const CUSTOM_TYPE: &str = "native_goal_descendant_deferral_v1";
pub(crate) const PREPARED_KEY: &str = "nativeDeferredContinuation";
pub(crate) const TOKEN_KEY: &str = "nativeDeferralId";
const CLOCK_SKEW_MS: u64 = 60_000;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Deferral {
    version: u32,
    pub(crate) deferral_id: String,
    pub(crate) session_id: String,
    pub(crate) worker_id: String,
    pub(crate) journal_path: String,
    owner_leaf_id: String,
    pub(crate) recorded_at_ms: u64,
    goal: GoalState,
}

#[derive(Clone, Debug)]
pub(crate) struct Recovery {
    pub(crate) intent: Deferral,
    pub(crate) prepared: Option<CustomMessage>,
}

fn same_goal(current: &GoalState, old: &GoalState) -> bool {
    current.status == GoalStatus::Active
        && current.goal_id.is_some()
        && current.goal_id == old.goal_id
        && current.objective == old.objective
        && current.created_at == old.created_at
        && current.token_budget == old.token_budget
        && current.tokens_used >= old.tokens_used
}

fn inspect<'a>(
    session_id: &str,
    current: &GoalState,
    entries: impl IntoIterator<Item = &'a FileEntry>,
    now: u64,
) -> Option<Recovery> {
    let mut prepared: Option<Value> = None;
    for entry in entries {
        match entry {
            FileEntry::SessionInfo { .. } | FileEntry::ChildUsageAttributed { .. } => continue,
            FileEntry::SessionState { payload, .. }
                if payload.state.status == pa_types::session::SessionStateStatus::Active =>
            {
                continue
            }
            _ => {}
        }
        let FileEntry::Custom { payload, base } = entry else {
            return None; // Any accepted work, branch change or other owner action wins.
        };
        let data = payload.data.as_ref()?;
        if payload.custom_type == pa_core::goals::GOAL_STATE_CUSTOM_TYPE {
            let row: GoalState = serde_json::from_value(data.clone()).ok()?;
            if row.status != GoalStatus::Active || row.goal_id != current.goal_id {
                return None;
            }
            if prepared.is_none() {
                prepared = data.get(PREPARED_KEY).cloned();
            }
            continue;
        }
        if payload.custom_type != CUSTOM_TYPE {
            return None;
        }
        let intent: Deferral = serde_json::from_value(data.clone()).ok()?;
        if intent.version != 1
            || intent.session_id != session_id
            || intent.deferral_id.is_empty()
            || intent.owner_leaf_id.is_empty()
            || base.parent_id.as_deref() != Some(intent.owner_leaf_id.as_str())
            || intent.recorded_at_ms > now.saturating_add(CLOCK_SKEW_MS)
            || !same_goal(current, &intent.goal)
        {
            return None;
        }
        let prepared = if current.continuations_used == intent.goal.continuations_used {
            if current.no_progress_streak != intent.goal.no_progress_streak
                || current.no_progress_turn_ms != intent.goal.no_progress_turn_ms
            {
                return None;
            }
            None
        } else if current.continuations_used == intent.goal.continuations_used.checked_add(1)? {
            let prepared = prepared?;
            if prepared["version"] != 1 || prepared["deferralId"] != intent.deferral_id {
                return None;
            }
            let prepared_goal: GoalState = serde_json::from_value(prepared["goal"].clone()).ok()?;
            if !same_goal(current, &prepared_goal)
                || current.continuations_used != prepared_goal.continuations_used
                || current.no_progress_streak != prepared_goal.no_progress_streak
                || current.no_progress_turn_ms != prepared_goal.no_progress_turn_ms
            {
                return None;
            }
            let message: CustomMessage =
                serde_json::from_value(prepared["message"].clone()).ok()?;
            let details = message.details.as_ref()?;
            if message.custom_type != pa_core::goals::GOAL_CONTEXT_CUSTOM_TYPE
                || details[TOKEN_KEY] != intent.deferral_id
                || details["goalId"].as_str() != current.goal_id.as_deref()
                || details["continuationsUsed"] != current.continuations_used
            {
                return None;
            }
            Some(message)
        } else {
            return None;
        };
        return Some(Recovery { intent, prepared });
    }
    None
}

pub(crate) type Sink =
    std::sync::Arc<dyn Fn(Option<&GoalState>) -> anyhow::Result<Option<Recovery>> + Send + Sync>;

pub(crate) fn persist(
    store: &mut crate::session_store::SessionFile,
    goal: &GoalState,
    worker_id: &str,
    journal_path: &Path,
) -> anyhow::Result<Recovery> {
    let certified = crate::session_store::SessionFile::open_windowed(&store.path)?;
    anyhow::ensure!(
        certified.skipped_lines == 0,
        "Deferred goal authority has unreadable entries"
    );
    if let Some(existing) = from_file(&store.path) {
        anyhow::ensure!(
            existing.intent.worker_id == worker_id
                && Path::new(&existing.intent.journal_path) == journal_path,
            "Deferred goal belongs to another native owner"
        );
        anyhow::ensure!(
            same_goal(goal, &existing.intent.goal),
            "Deferred goal authority belongs to another goal revision"
        );
        return Ok(existing);
    }
    anyhow::ensure!(
        goal.status == GoalStatus::Active && goal.goal_id.is_some(),
        "No active goal boundary"
    );
    let intent = Deferral {
        version: 1,
        deferral_id: uuid::Uuid::new_v4().to_string(),
        session_id: store.session_id().to_string(),
        worker_id: worker_id.to_string(),
        journal_path: journal_path.to_string_lossy().to_string(),
        owner_leaf_id: store
            .leaf_id()
            .ok_or_else(|| anyhow::anyhow!("Goal boundary has no accepted branch leaf"))?
            .to_string(),
        recorded_at_ms: crate::util::now_ms(),
        goal: goal.clone(),
    };
    store.persist_entry(
        "custom",
        serde_json::json!({"customType":CUSTOM_TYPE,"data":intent}),
    )?;
    Ok(Recovery {
        intent,
        prepared: None,
    })
}

pub(crate) fn cancel(store: &mut crate::session_store::SessionFile) -> anyhow::Result<()> {
    if from_file(&store.path).is_some() {
        store.persist_entry(
            "custom",
            serde_json::json!({"customType":CUSTOM_TYPE,"data":{"version":1,"cancelled":true}}),
        )?;
    }
    Ok(())
}

pub(crate) fn from_file(path: &Path) -> Option<Recovery> {
    let window = pa_core::session::window::WindowedSessionStore::open(path)
        .ok()
        .flatten()?;
    let goal = window.goal_state()?;
    let header_id = window.entries().iter().find_map(|entry| match entry {
        FileEntry::Header { header } => Some(header.id.as_str()),
        _ => None,
    })?;
    let mut branch = Vec::new();
    let mut id = Some(window.leaf_id());
    for _ in 0..=window.entries().len() {
        let Some(entry) =
            id.and_then(|id| window.entries().iter().find(|entry| entry.id() == Some(id)))
        else {
            break;
        };
        branch.push(entry);
        id = entry.parent_id();
    }
    inspect(header_id, goal, branch, crate::util::now_ms())
}

pub(crate) fn started(journal: &Path, token: &str) -> bool {
    // Unreadable admission history is uncertainty, never permission to replay.
    crate::journal::WorkerRecoveryJournal::read_message_facts(journal).map_or(true, |facts| {
        facts
            .values()
            .any(|fact| fact.message_id == format!("goal-deferral:{token}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn persist(
        store: &mut crate::session_store::SessionFile,
        goal: &GoalState,
    ) -> anyhow::Result<Recovery> {
        let journal = store.path.with_extension("journal");
        super::persist(store, goal, "retained-worker", &journal)
    }

    fn fixture() -> (
        tempfile::TempDir,
        crate::session_store::SessionFile,
        GoalState,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let mut store = crate::session_store::SessionFile::create("/test", None, 0);
        store.set_path(dir.path().join("session.jsonl"));
        store.rewrite().unwrap();
        let goal = GoalState {
            active: true,
            status: GoalStatus::Active,
            goal_id: Some("goal".into()),
            objective: Some("continue after child".into()),
            created_at: Some(1),
            ..GoalState::default()
        };
        store
            .persist_entry(
                "custom",
                json!({"customType":pa_core::goals::GOAL_STATE_CUSTOM_TYPE,"data":goal}),
            )
            .unwrap();
        (dir, store, goal)
    }

    #[test]
    fn worker_owned_intent_survives_reopen_without_a_user_row() {
        let (_dir, mut store, goal) = fixture();
        let recovery = persist(&mut store, &goal).unwrap();
        let actual = from_file(&store.path).expect("durable native boundary");
        assert_eq!(actual.intent.session_id, store.session_id());
        assert_eq!(actual.intent.deferral_id, recovery.intent.deferral_id);
        assert!(actual.prepared.is_none());
        assert_eq!(
            persist(&mut store, &goal).unwrap().intent.deferral_id,
            recovery.intent.deferral_id
        );
    }

    #[test]
    fn native_create_metadata_preserves_intent_but_archived_state_does_not() {
        let (_dir, mut store, goal) = fixture();
        let token = persist(&mut store, &goal).unwrap().intent.deferral_id;
        for _ in 0..2 {
            store
                .persist_entry("session_state", json!({"state":{"status":"active"}}))
                .unwrap();
            store
                .persist_entry("session_info", json!({"name":"retained worker"}))
                .unwrap();
            assert_eq!(from_file(&store.path).unwrap().intent.deferral_id, token);
        }
        store
            .persist_entry("session_state", json!({"state":{"status":"archived"}}))
            .unwrap();
        assert!(from_file(&store.path).is_none());
    }

    #[test]
    fn long_wait_goal_bookkeeping_preserves_native_intent() {
        let (_dir, mut store, mut goal) = fixture();
        let token = persist(&mut store, &goal).unwrap().intent.deferral_id;
        for _ in 0..64 {
            goal.tokens_used += 1;
            store
                .persist_entry(
                    "custom",
                    json!({"customType":pa_core::goals::GOAL_STATE_CUSTOM_TYPE,"data":goal}),
                )
                .unwrap();
        }
        assert_eq!(from_file(&store.path).unwrap().intent.deferral_id, token);
    }

    #[test]
    fn another_worker_or_fresh_journal_cannot_adopt_retained_intent() {
        let (_dir, mut store, goal) = fixture();
        let original = persist(&mut store, &goal).unwrap();
        let journal = store.path.with_extension("journal");
        assert!(super::persist(&mut store, &goal, "different-worker", &journal).is_err());
        assert!(super::persist(
            &mut store,
            &goal,
            "retained-worker",
            &journal.with_extension("fresh")
        )
        .is_err());
        assert_eq!(
            from_file(&store.path).unwrap().intent.deferral_id,
            original.intent.deferral_id
        );
    }

    #[test]
    fn compacted_branch_requires_a_new_native_deferral_boundary() {
        let (_dir, mut store, goal) = fixture();
        let old = persist(&mut store, &goal).unwrap().intent.deferral_id;
        store
            .persist_entry(
                "compaction",
                json!({"summary":"compacted","firstKeptEntryId":store.leaf_id(),"tokensBefore":1}),
            )
            .unwrap();
        assert!(from_file(&store.path).is_none());
        let fresh = persist(&mut store, &goal).unwrap();
        assert_ne!(fresh.intent.deferral_id, old);
        assert_eq!(
            from_file(&store.path).unwrap().intent.deferral_id,
            fresh.intent.deferral_id
        );
    }

    #[test]
    fn explicit_cancel_and_accepted_work_invalidate_intent() {
        let (_dir, mut store, goal) = fixture();
        persist(&mut store, &goal).unwrap();
        cancel(&mut store).unwrap();
        assert!(from_file(&store.path).is_none());
        persist(&mut store, &goal).unwrap();
        store
            .persist_entry(
                "message",
                json!({"message":{"role":"user","content":"new owner work"}}),
            )
            .unwrap();
        assert!(from_file(&store.path).is_none());
    }

    #[test]
    fn prepared_payload_is_exact_and_progress_changes_do_not_lose_the_charge() {
        for streak in [None, Some(0), Some(2)] {
            let (_dir, mut store, goal) = fixture();
            let recovery = persist(&mut store, &goal).unwrap();
            let mut next = goal.clone();
            next.continuations_used += 1;
            next.no_progress_streak = streak;
            next.no_progress_turn_ms = Some(123);
            next.tokens_used = 17;
            let message = json!({"customType":pa_core::goals::GOAL_CONTEXT_CUSTOM_TYPE,"content":"exact payload","timestamp":123,"display":false,"details":{"nativeDeferralId":recovery.intent.deferral_id,"goalId":"goal","continuationsUsed":1}});
            let mut data = serde_json::to_value(&next).unwrap();
            data[PREPARED_KEY] = json!({"version":1,"deferralId":recovery.intent.deferral_id,"message":message,"goal":next});
            store
                .persist_entry(
                    "custom",
                    json!({"customType":pa_core::goals::GOAL_STATE_CUSTOM_TYPE,"data":data}),
                )
                .unwrap();
            let reopened = from_file(&store.path).expect("charged prepared boundary");
            assert_eq!(
                serde_json::to_value(reopened.prepared.unwrap()).unwrap(),
                message
            );
        }
    }

    #[test]
    fn terminal_wrong_goal_future_and_wrong_session_are_not_authority() {
        for mutation in ["terminal", "goal", "future", "session"] {
            let (_dir, mut store, goal) = fixture();
            let mut intent = persist(&mut store, &goal).unwrap().intent;
            match mutation {
                "future" => intent.recorded_at_ms = u64::MAX,
                "session" => intent.session_id = "another session".into(),
                _ => {}
            }
            if matches!(mutation, "future" | "session") {
                intent.owner_leaf_id = store.leaf_id().unwrap().to_string();
                store
                    .persist_entry("custom", json!({"customType":CUSTOM_TYPE,"data":intent}))
                    .unwrap();
            } else {
                let mut next = goal;
                if mutation == "terminal" {
                    next.status = GoalStatus::Paused;
                    next.active = false;
                } else {
                    next.goal_id = Some("different".into());
                }
                store
                    .persist_entry(
                        "custom",
                        json!({"customType":pa_core::goals::GOAL_STATE_CUSTOM_TYPE,"data":next}),
                    )
                    .unwrap();
            }
            assert!(from_file(&store.path).is_none(), "{mutation}");
        }
    }
}
