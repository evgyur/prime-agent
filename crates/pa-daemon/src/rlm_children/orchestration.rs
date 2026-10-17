//! Task-scoped orchestration accounting. No task text or automatic worker admission.
use super::*;
use serde::{Deserialize, Serialize};

pub(crate) const DEFAULT_CORRECTIVE_BUDGET: u32 = 2;
pub(crate) const MAX_CORRECTIVE_BUDGET: u32 = 5;
pub(crate) const DEFAULT_MIN_ACTIVE: usize = 5;
pub(crate) const MAX_ACTIVE: usize = 20;
const SNAPSHOT_TIMEOUT_MS: u64 = 2_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Policy {
    version: u32,
    enabled: bool,
    min_active: usize,
    pub(super) max_active: usize,
    root_writes_code: bool,
    #[serde(default = "default_budget")]
    corrective_budget: u32,
}
fn default_budget() -> u32 {
    DEFAULT_CORRECTIVE_BUDGET
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Task {
    project_id: String,
    plan_id: String,
    step_id: String,
    task_generation: u64,
    policy_revision: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Assignment {
    child_id: String,
    admission_generation: String,
    incarnation: String,
    assignment_id: String,
    task_generation: u64,
    ownership: String,
    acceptance_ref: String,
    artifact_ref: String,
    dependencies_satisfied: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Exception {
    reason: String,
    evidence: String,
    dependency: String,
    clear_condition: String,
    task_generation: u64,
    policy_revision: u64,
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Gate {
    pub(super) revision: u64,
    pub(super) policy: Option<Policy>,
    task: Option<Task>,
    assignments: Vec<Assignment>,
    exception: Option<Exception>,
    pub(super) attempts: u32,
    #[serde(default)]
    pub(super) suspended: bool,
    #[serde(default)]
    pub(super) correction_pending: bool,
    #[serde(default)]
    pending_revision: u64,
    #[serde(default)]
    pub(super) next_work_enabled: bool,
    #[serde(skip)]
    pub(super) next_work_source: Option<super::next_work::Source>,
    #[serde(skip)]
    pub(super) next_work: Option<Value>,
    #[serde(default)]
    pub(super) work_bindings: Vec<super::next_work::Binding>,
}
impl Gate {
    pub(super) fn enabled(&self) -> bool {
        self.policy.as_ref().is_some_and(|p| p.enabled)
    }
    fn same_task(&self, task: &Task) -> bool {
        self.task.as_ref().is_some_and(|t| {
            t.project_id == task.project_id
                && t.plan_id == task.plan_id
                && t.step_id == task.step_id
                && t.task_generation == task.task_generation
        })
    }
}

impl SupervisorChildSessions {
    #[cfg(test)]
    pub(crate) fn inner_disable_gate_for_test(&self) {
        let mut gate = self.inner.gate.lock().expect("gate lock");
        if let Some(policy) = &mut gate.policy {
            policy.enabled = false;
        }
        gate.revision += 1;
    }
    pub(crate) fn gate_correction_permit(&self) -> Value {
        let gate = self.inner.gate.lock().expect("gate lock");
        json!({"revision":gate.pending_revision,"attempt":gate.attempts,"taskGeneration":gate.task.as_ref().map(|task|task.task_generation)})
    }
    pub(crate) fn gate_permit_is_current(&self, permit: &Value) -> bool {
        let gate = self.inner.gate.lock().expect("gate lock");
        gate.enabled()
            && !gate.suspended
            && gate.exception.is_none()
            && gate.correction_pending
            && permit["revision"].as_u64() == Some(gate.revision)
            && permit["attempt"].as_u64() == Some(u64::from(gate.attempts))
            && permit["taskGeneration"].as_u64()
                == gate.task.as_ref().map(|task| task.task_generation)
    }
    pub(crate) fn gate_correction_is_current(&self) -> bool {
        let gate = self.inner.gate.lock().expect("gate lock");
        gate.enabled()
            && !gate.suspended
            && gate.exception.is_none()
            && gate.correction_pending
            && gate.pending_revision == gate.revision
    }
    pub(crate) fn consume_gate_correction(&self) {
        self.inner
            .gate
            .lock()
            .expect("gate lock")
            .correction_pending = false;
    }
    pub(crate) fn gate_stops_continuation(&self) -> bool {
        let gate = self.inner.gate.lock().expect("gate lock");
        gate.suspended || gate.enabled()
    }
    fn gate_path(&self) -> Option<PathBuf> {
        self.inner
            .identity
            .lock()
            .expect("identity lock")
            .session_file
            .as_ref()
            .map(|file| PathBuf::from(format!("{file}.orchestration-gate.json")))
    }
    pub(super) fn persist_gate(&self, gate: &Gate) -> Result<()> {
        if let Some(path) = self.gate_path() {
            let temp = path.with_extension(format!("{}.tmp", uuid::Uuid::new_v4()));
            let mut options = std::fs::OpenOptions::new();
            options.create_new(true).write(true);
            pa_core::platform::perms::set_private_mode(&mut options);
            use std::io::Write;
            let mut file = options.open(&temp)?;
            file.write_all(&serde_json::to_vec(gate)?)?;
            file.sync_all()?;
            pa_core::platform::rename_onto(&temp, &path)?;
        }
        Ok(())
    }
    pub(crate) fn restore_gate(&self) {
        let Some(path) = self.gate_path() else {
            return;
        };
        if !path.exists() {
            return;
        }
        let restored = std::fs::read(&path)
            .map_err(anyhow::Error::from)
            .and_then(|data| serde_json::from_slice::<Gate>(&data).map_err(Into::into));
        let mut gate = self.inner.gate.lock().expect("gate lock");
        match restored {
            Ok(mut state) => {
                state.suspended = state.enabled();
                state.correction_pending = false;
                *gate = state;
            }
            Err(error) => {
                // A corrupt enabled policy must never degrade to disabled.
                gate.suspended = true;
                eprintln!("pa-daemon: orchestration policy recovery failed: {error:#}");
            }
        }
    }
    pub(crate) async fn configure_gate(&self, payload: &Value) -> Result<Value> {
        anyhow::ensure!(
            self.inner.identity.lock().expect("identity lock").rlm_depth == 0,
            "Only a root session may configure its orchestration gate"
        );
        anyhow::ensure!(
            payload.get("nextWorkSource").is_none()
                && payload.get("nextWork").is_none()
                && payload.get("invalidateNextWork").is_none(),
            "next_work source is installed only by the Studio owner"
        );
        let policy: Policy = serde_json::from_value(payload["policy"].clone())?;
        let task: Task = serde_json::from_value(payload["task"].clone())?;
        anyhow::ensure!(
            policy.version == 1
                && (1..=MAX_ACTIVE).contains(&policy.min_active)
                && (policy.min_active..=MAX_ACTIVE).contains(&policy.max_active)
                && policy.corrective_budget <= MAX_CORRECTIVE_BUDGET,
            "Invalid orchestration v1 policy"
        );
        anyhow::ensure!(
            [&task.project_id, &task.plan_id, &task.step_id]
                .iter()
                .all(|s| !s.trim().is_empty())
                && (1..=9_007_199_254_740_991).contains(&task.task_generation),
            "Task refs are required"
        );
        let assignments: Vec<Assignment> = serde_json::from_value(payload["assignments"].clone())?;
        let exception: Option<Exception> = payload
            .get("exception")
            .filter(|v| !v.is_null())
            .map(|value| serde_json::from_value(value.clone()))
            .transpose()?;
        let binding_rows = if assignments.is_empty() {
            Vec::new()
        } else {
            self.accounting_rows().await
        };
        let mut ids = std::collections::HashSet::new();
        let mut owners = std::collections::HashSet::new();
        let mut children = std::collections::HashSet::new();
        for a in &assignments {
            anyhow::ensure!(
                [
                    &a.child_id,
                    &a.admission_generation,
                    &a.incarnation,
                    &a.assignment_id,
                    &a.ownership,
                    &a.acceptance_ref,
                    &a.artifact_ref
                ]
                .iter()
                .all(|s| !s.trim().is_empty())
                    && a.task_generation == task.task_generation
                    && ids.insert(&a.assignment_id)
                    && owners.insert(&a.ownership)
                    && children.insert(&a.child_id),
                "Invalid or duplicate assignment refs"
            );
            anyhow::ensure!(
                binding_rows.iter().any(|row| row["childId"] == a.child_id
                    && row["admissionGeneration"] == a.admission_generation
                    && row["incarnation"] == a.incarnation),
                "Current worker incarnation required; reconcile replacements before rebinding"
            );
            let record = self
                .inner
                .find_record(&a.child_id)
                .await
                .ok_or_else(|| anyhow!("Unknown child binding"))?;
            anyhow::ensure!(
                record.lock().await.admission_generation.as_deref()
                    == Some(&a.admission_generation),
                "Stale child admission generation"
            );
        }
        if let Some(e) = &exception {
            anyhow::ensure!(
                [&e.reason, &e.evidence, &e.dependency, &e.clear_condition]
                    .iter()
                    .all(|s| !s.trim().is_empty())
                    && e.task_generation == task.task_generation
                    && e.policy_revision == task.policy_revision,
                "Exception needs current task/revision and evidence"
            );
        }
        {
            let mut guard = self.inner.gate.lock().expect("gate lock");
            anyhow::ensure!(
                payload["expectedRevision"].as_u64() == Some(guard.revision),
                "Orchestration revision conflict"
            );
            let mut next = guard.clone();
            if !next.same_task(&task) {
                next.attempts = 0;
            }
            next.revision += 1;
            next.policy = Some(policy);
            next.task = Some(task);
            next.assignments = assignments;
            next.exception = exception;
            next.suspended = false;
            self.persist_gate(&next)?;
            *guard = next;
        }
        Ok(self.gate_status().await)
    }
    pub(crate) async fn gate_status(&self) -> Value {
        self.refresh_next_work().await;
        let gate = self.inner.gate.lock().expect("gate lock").clone();
        let epoch = self
            .inner
            .accounting_epoch
            .load(std::sync::atomic::Ordering::SeqCst);
        let rows = self.accounting_rows().await;
        let current_revision = self.inner.gate.lock().expect("gate lock").revision;
        let revision_changed = current_revision != gate.revision
            || epoch
                != self
                    .inner
                    .accounting_epoch
                    .load(std::sync::atomic::Ordering::SeqCst);
        let mut active = 0;
        let mut unknown = 0;
        for assignment in &gate.assignments {
            match rows.iter().find(|row| assignment_matches(assignment, row)) {
                Some(row)
                    if row["executionKind"] == "executing" && assignment.dependencies_satisfied =>
                {
                    active += 1
                }
                Some(row) if row["executionKind"] != "unknown" => {}
                _ => unknown += 1,
            }
        }
        // Unbound obligations are visible unknown, never counted as active.
        unknown += rows
            .iter()
            .filter(|row| {
                row["obligation"] == true
                    && !gate.assignments.iter().any(|a| {
                        row["childId"] == a.child_id
                            && row["admissionGeneration"] == a.admission_generation
                            && row["incarnation"] == a.incarnation
                    })
            })
            .count();
        let next_work = self.next_work_view(&gate, &rows);
        let decision = if revision_changed {
            "unknown"
        } else if gate.suspended {
            "suspended"
        } else if !gate.enabled() {
            "disabled"
        } else if gate.next_work_enabled && next_work["complete"] != true {
            "unknown"
        } else if gate.next_work_enabled && next_work["actionRequired"] == true {
            if gate.attempts >= gate.policy.as_ref().map_or(0, |p| p.corrective_budget) {
                "suspended"
            } else {
                "corrective"
            }
        } else if gate.next_work_enabled {
            "pass"
        } else if gate.exception.is_some() {
            "exception"
        } else if unknown == 0
            && active
                >= gate
                    .policy
                    .as_ref()
                    .map_or(DEFAULT_MIN_ACTIVE, |p| p.min_active)
        {
            "pass"
        } else if gate.attempts >= gate.policy.as_ref().map_or(0, |p| p.corrective_budget) {
            "suspended"
        } else if unknown > 0 {
            "unknown"
        } else {
            "corrective"
        };
        json!({"version":1,"activeSessionId":self.inner.parent_active_session_id,
            "sessionId":self.inner.identity.lock().expect("identity lock").session_id,
            "revision":gate.revision,"accountingEpoch":epoch,"task":gate.task,"policy":gate.policy,
            "decision":decision,"knownActive":active,"unknown":unknown,"observedAt":now_ms(),
            "complete":unknown==0 && !gate.suspended && !revision_changed,"exception":gate.exception,
            "correctiveAttempts":gate.attempts,"assignments":rows,
            "nextWorkSourceInstanceId":gate.next_work_source.as_ref().map(|source| source.instance_id.as_str()),"nextWork":next_work,"rootWritesCodeEnforcement":"policy-audit-only"})
    }
    pub(crate) async fn gate_correction(&self) -> Option<String> {
        if !self.gate_stops_continuation() {
            return None;
        }
        let status = self.gate_status().await;
        if !matches!(status["decision"].as_str(), Some("corrective" | "unknown")) {
            return None;
        }
        let mut gate = self.inner.gate.lock().expect("gate lock");
        if status["accountingEpoch"].as_u64()
            != Some(
                self.inner
                    .accounting_epoch
                    .load(std::sync::atomic::Ordering::SeqCst),
            )
            || status["revision"].as_u64() != Some(gate.revision)
            || !gate.enabled()
            || gate.suspended
            || gate.correction_pending
            || gate.exception.is_some()
            || gate.attempts >= gate.policy.as_ref()?.corrective_budget
        {
            return None;
        }
        gate.attempts += 1;
        gate.correction_pending = true;
        gate.pending_revision = gate.revision;
        if let Err(error) = self.persist_gate(&gate) {
            gate.suspended = true;
            eprintln!("pa-daemon: orchestration attempt persistence failed: {error:#}");
            return None;
        }
        if gate.next_work_enabled {
            return Some(format!("[next-work]\nCurrent owner-scoped Roadmap and runtime projection: {}. Accept completed artifacts first, then start an uncovered ready branch with rlm.spawn(..., work={{planId,stepId,snapshotRevision}}). UNKNOWN reserves capacity; never resend it. Files remain owned until confirmed STOP and acceptance/handoff. If no safe action exists, report the exact dependency and suspend. No fake work or silent scope reduction. Correction {} of {}.", status["nextWork"], gate.attempts, gate.policy.as_ref()?.corrective_budget));
        }
        Some(format!("[orchestration-gate]\nTask-linked executing workers: {}; unknown: {}. Reconcile current assignments with rlm.orchestration_status(), then bind real work with rlm.configure_orchestration_gate(payload), or record an evidence-backed exception. UNKNOWN delivery must not be resent. No fake work. This does not complete a goal. Corrective attempt {} of {}.",
            status["knownActive"],status["unknown"],gate.attempts,gate.policy.as_ref()?.corrective_budget))
    }
    pub(crate) async fn assert_gate_capacity(&self) -> Result<()> {
        let limit = {
            let gate = self.inner.gate.lock().expect("gate lock");
            if !gate.enabled() {
                return Ok(());
            }
            gate.policy.as_ref().map_or(MAX_ACTIVE, |p| p.max_active)
        };
        let records = self.inner.children.lock().await.clone();
        let mut reserved = 0;
        for record in records {
            let row = record.lock().await;
            if !row.settled || row.admission_blocked {
                reserved += 1;
            }
        }
        anyhow::ensure!(
            reserved < limit,
            "Orchestration max admission capacity reached (UNKNOWN reserves capacity)"
        );
        Ok(())
    }
    pub(crate) async fn accounting_rows(&self) -> Vec<Value> {
        let records = self.inner.children.lock().await.clone();
        use futures::StreamExt;
        futures::stream::iter(records).map(|record| async move {
            let (id, selector, generation, expected, blocked, obligation)={let row=record.lock().await;
                (row.rlm_child_id.clone(),durable_child_selector(row.session_id.as_deref(),&row.rlm_child_id),
                 row.admission_generation.clone(),row.expected_message_id.clone(),row.admission_blocked,!row.settled)};
            let command=DaemonCommand::GetState{id:None,active_session_id:selector,rest:Map::default()};
            let state=self.inner.command(&command,SNAPSHOT_TIMEOUT_MS).await.ok();
            let current=record.lock().await;
            let kind=if blocked || current.admission_blocked || current.admission_generation!=generation || generation.is_none() { "unknown" }
                else if current.settled { "idle" }
                else { execution_kind(state.as_ref(),expected.as_deref()) };
            json!({"childId":id,"admissionGeneration":generation,"expectedMessageId":expected,
                "executionKind":kind,"obligation":obligation,"incarnation":state.as_ref().and_then(|s|s.get("workerInstanceId")),
                "observedAt":now_ms()})
        }).buffer_unordered(4).collect().await
    }
}
fn assignment_matches(a: &Assignment, row: &Value) -> bool {
    row["childId"] == a.child_id
        && row["admissionGeneration"] == a.admission_generation
        && row["incarnation"] == a.incarnation
}
fn execution_kind(state: Option<&Value>, expected: Option<&str>) -> &'static str {
    let Some(s) = state else {
        return "unknown";
    };
    if s["workerInstanceId"].as_str().is_none_or(str::is_empty) {
        return "unknown";
    }
    if s["isCompacting"] == true || s["isQuotaParked"] == true {
        return "maintenance";
    }
    let started = s["ownExecutionStarted"].as_bool();
    let Some(ids) = s["runningMessageIds"].as_array() else {
        return "unknown";
    };
    if started == Some(true) && expected.is_some_and(|id| ids.iter().any(|v| v == id)) {
        return "executing";
    }
    if s["isStreaming"] == true || s["sessionActions"]["queuedCount"].as_u64().unwrap_or(0) > 0 {
        return "queued";
    }
    if s["hasBackgroundBash"] == true {
        return "unknown";
    } // no job-generation ack yet
    "idle"
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn retask_requires_current_message_start_not_old_busy_or_queue() {
        let mut state = json!({"workerInstanceId":"new-worker","isStreaming":true,
            "ownExecutionStarted":true,"runningMessageIds":["old"],"sessionActions":{"queuedCount":1}});
        assert_eq!(execution_kind(Some(&state), Some("new")), "queued");
        state["runningMessageIds"] = json!(["new"]);
        assert_eq!(execution_kind(Some(&state), Some("new")), "executing");
        state["ownExecutionStarted"] = json!(false);
        assert_eq!(execution_kind(Some(&state), Some("new")), "queued");
        state["workerInstanceId"] = Value::Null;
        assert_eq!(execution_kind(Some(&state), Some("new")), "unknown");
    }
    fn sessions() -> SupervisorChildSessions {
        SupervisorChildSessions::new(
            Arc::new(crate::supervisor_link::SupervisorLink::new(PathBuf::new())),
            std::env::temp_dir(),
            "parent".into(),
            Arc::new(crate::model_allowlist::ModelRefusalTelemetry::new(
                std::env::temp_dir(),
                true,
            )),
        )
    }
    fn configure(budget: u32) -> Value {
        json!({"expectedRevision":0,"policy":{"version":1,"enabled":true,"minActive":5,
            "maxActive":20,"rootWritesCode":false,"correctiveBudget":budget},
            "task":{"projectId":"p","planId":"plan","stepId":"step","taskGeneration":1,"policyRevision":1},
            "assignments":[]})
    }
    #[tokio::test]
    async fn budget_is_bounded_and_reads_or_policy_revision_do_not_reset_it() {
        let sessions = sessions();
        let mut config = configure(2);
        assert_eq!(
            sessions.configure_gate(&config).await.unwrap()["decision"],
            "corrective"
        );
        assert!(sessions.gate_correction().await.is_some());
        for _ in 0..4 {
            assert_eq!(sessions.gate_status().await["correctiveAttempts"], 1);
        }
        config["expectedRevision"] = json!(1);
        config["task"]["policyRevision"] = json!(2);
        sessions.configure_gate(&config).await.unwrap();
        assert!(sessions.gate_correction().await.is_none());
        sessions.consume_gate_correction();
        assert!(sessions.gate_correction().await.is_some());
        assert!(sessions.gate_correction().await.is_none());
        assert_eq!(sessions.gate_status().await["decision"], "suspended");
        config["expectedRevision"] = json!(2);
        config["task"]["taskGeneration"] = json!(2);
        assert_eq!(
            sessions.configure_gate(&config).await.unwrap()["correctiveAttempts"],
            0
        );
    }
    #[tokio::test]
    async fn zero_budget_safe_exit_and_exception_requires_current_evidence() {
        let sessions = sessions();
        let mut config = configure(0);
        assert_eq!(
            sessions.configure_gate(&config).await.unwrap()["decision"],
            "suspended"
        );
        assert!(sessions.gate_correction().await.is_none());
        config["expectedRevision"] = json!(1);
        config["exception"] = json!({"reason":"input","evidence":"roadmap step needs approval",
            "dependency":"user authority","clearCondition":"approval received","taskGeneration":1,"policyRevision":0});
        assert!(sessions.configure_gate(&config).await.is_err());
        config["exception"]["policyRevision"] = json!(1);
        assert_eq!(
            sessions.configure_gate(&config).await.unwrap()["decision"],
            "exception"
        );
        assert!(sessions.gate_correction().await.is_none());
    }
    #[tokio::test]
    async fn recovery_keeps_budget_and_requires_explicit_reconciliation() {
        let sessions = sessions();
        let temp = tempfile::TempDir::new().unwrap();
        sessions.set_identity(ParentIdentity {
            session_file: Some(temp.path().join("session.jsonl").display().to_string()),
            ..ParentIdentity::with_default_depth()
        });
        sessions.configure_gate(&configure(2)).await.unwrap();
        sessions.gate_correction().await.unwrap();
        sessions.restore_gate();
        let status = sessions.gate_status().await;
        assert_eq!(status["decision"], "suspended");
        assert_eq!(status["correctiveAttempts"], 1);
        assert!(sessions.gate_correction().await.is_none());
    }
    #[test]
    fn five_queued_or_maintenance_rows_are_never_execution() {
        let states = [
            json!({"workerInstanceId":"w","isStreaming":false,"ownExecutionStarted":false,
            "runningMessageIds":[],"sessionActions":{"queuedCount":1}}),
            json!({"workerInstanceId":"w","isStreaming":true,"ownExecutionStarted":true,
                "runningMessageIds":["new"],"isCompacting":true}),
        ];
        for s in states {
            assert_ne!(execution_kind(Some(&s), Some("new")), "executing");
        }
    }

    #[tokio::test]
    async fn studio_numeric_generation_roundtrip_rejects_strings_zero_and_unsafe_integer() {
        let sessions = sessions();
        let valid = configure(2);
        let status = sessions.configure_gate(&valid).await.unwrap();
        assert_eq!(status["task"]["taskGeneration"], 1);
        for generation in [json!("1"), json!(0), json!(9_007_199_254_740_992u64)] {
            let mut invalid = valid.clone();
            invalid["expectedRevision"] = json!(1);
            invalid["task"]["taskGeneration"] = generation;
            assert!(sessions.configure_gate(&invalid).await.is_err());
        }
    }

    #[tokio::test]
    async fn settle_or_config_mutation_during_snapshot_never_returns_complete_pass() {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        use tokio::sync::oneshot;
        let dir = tempfile::TempDir::new().unwrap();
        let socket = dir.path().join("fake.sock");
        let listener = pa_types::platform::transport::bind_transport(&socket)
            .await
            .unwrap();
        let sessions = SupervisorChildSessions::new(
            Arc::new(crate::supervisor_link::SupervisorLink::new(socket)),
            dir.path().into(),
            "parent".into(),
            Arc::new(crate::model_allowlist::ModelRefusalTelemetry::new(
                dir.path().into(),
                true,
            )),
        );
        sessions.configure_gate(&configure(2)).await.unwrap();
        sessions
            .push_test_child(RlmChildIdentity {
                rlm_child_id: "child".into(),
                active_session_id: "child".into(),
                session_id: None,
                session_name: "child".into(),
            })
            .await;
        let record = sessions.inner.children.lock().await[0].clone();
        {
            let mut row = record.lock().await;
            row.admission_generation = Some("generation".into());
            row.expected_message_id = Some("message".into());
        }
        let (started_tx, started_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        tokio::spawn(async move {
            let (stream, _) = {
                let stream = listener.accept().await.unwrap();
                (stream, ())
            };
            let (reader, mut writer) = stream.split();
            writer.write_all(b"{\"type\":\"daemon_hello\",\"protocol\":{\"name\":\"prime-agent.daemon\",\"version\":7}}\n").await.unwrap();
            let mut reader = BufReader::new(reader);
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();
            let request: Value = serde_json::from_str(&line).unwrap();
            started_tx.send(()).unwrap();
            release_rx.await.unwrap();
            let response = crate::protocol::response_success(
                request["id"].as_str(),
                "get_state",
                Some(json!({
                "workerInstanceId":"worker","ownExecutionStarted":true,"isStreaming":true,"runningMessageIds":["message"]})),
            );
            writer
                .write_all(format!("{}\n", serde_json::to_string(&response).unwrap()).as_bytes())
                .await
                .unwrap();
        });
        let read_sessions = sessions.clone();
        let reading = tokio::spawn(async move { read_sessions.gate_status().await });
        started_rx.await.unwrap();
        sessions
            .inner
            .accounting_epoch
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        record.lock().await.settled = true;
        {
            let mut gate = sessions.inner.gate.lock().unwrap();
            gate.revision += 1;
        }
        release_tx.send(()).unwrap();
        let status = reading.await.unwrap();
        assert_eq!(status["decision"], "unknown");
        assert_eq!(status["complete"], false);
        assert_eq!(status["knownActive"], 0);
    }

    #[test]
    fn four_started_and_one_admitted_queue_do_not_meet_minimum() {
        let active = json!({"workerInstanceId":"worker","ownExecutionStarted":true,
            "runningMessageIds":["new"],"isStreaming":true,"sessionActions":{"queuedCount":0}});
        let mut queued = active.clone();
        queued["ownExecutionStarted"] = json!(false);
        queued["sessionActions"]["queuedCount"] = json!(1);
        let mut observations = vec![active.clone(); 4];
        observations.push(queued);
        let count = observations
            .iter()
            .filter(|row| execution_kind(Some(row), Some("new")) == "executing")
            .count();
        assert_eq!(count, 4);
        assert!(count < DEFAULT_MIN_ACTIVE);
        observations[4] = active;
        assert_eq!(
            observations
                .iter()
                .filter(|row| execution_kind(Some(row), Some("new")) == "executing")
                .count(),
            5
        );
    }
    #[tokio::test]
    async fn child_cannot_configure_gate_or_impersonate_root_task() {
        let sessions = sessions();
        sessions.set_identity(ParentIdentity {
            rlm_depth: 1,
            ..ParentIdentity::with_default_depth()
        });
        let result = sessions.configure_gate(&configure(2)).await;
        assert!(format!("{:#}", result.unwrap_err()).contains("Only a root"));
        assert_eq!(sessions.inner.gate.lock().unwrap().revision, 0);
    }
    #[test]
    fn replacement_incarnation_does_not_match_existing_assignment_binding() {
        let assignment = Assignment {
            child_id: "kid".into(),
            admission_generation: "g".into(),
            incarnation: "worker-old".into(),
            assignment_id: "a".into(),
            task_generation: 1,
            ownership: "o".into(),
            acceptance_ref: "accept".into(),
            artifact_ref: "artifact".into(),
            dependencies_satisfied: true,
        };
        let row = json!({"childId":"kid","admissionGeneration":"g","incarnation":"worker-new","executionKind":"executing"});
        assert!(!assignment_matches(&assignment, &row));
        let reconciled = Assignment {
            incarnation: "worker-new".into(),
            ..assignment
        };
        assert!(assignment_matches(&reconciled, &row));
    }

    #[tokio::test]
    async fn disabled_after_mint_revokes_current_correction_permit() {
        let sessions = sessions();
        sessions.configure_gate(&configure(2)).await.unwrap();
        assert!(sessions.gate_correction().await.is_some());
        assert!(sessions.gate_correction_is_current());
        sessions.inner_disable_gate_for_test();
        assert!(!sessions.gate_correction_is_current());
    }
    #[tokio::test]
    async fn configurable_min_max_accept_valid_ranges_and_preserve_budget_bounds() {
        for (min, max) in [(1, 1), (3, 3), (3, 8), (5, 20)] {
            let sessions = sessions();
            let mut config = configure(2);
            config["policy"]["minActive"] = json!(min);
            config["policy"]["maxActive"] = json!(max);
            let status = sessions.configure_gate(&config).await.unwrap();
            assert_eq!(status["policy"]["minActive"], min);
            assert_eq!(status["policy"]["maxActive"], max);
            assert_eq!(status["decision"], "corrective");
            assert!(sessions.gate_correction().await.is_some());
            sessions.consume_gate_correction();
            assert!(sessions.gate_correction().await.is_some());
            sessions.consume_gate_correction();
            assert!(sessions.gate_correction().await.is_none());
            assert_eq!(sessions.gate_status().await["decision"], "suspended");
        }
        for (min, max) in [(0, 20), (3, 2), (1, 21), (21, 21), (1, 0)] {
            let sessions = sessions();
            let mut config = configure(2);
            config["policy"]["minActive"] = json!(min);
            config["policy"]["maxActive"] = json!(max);
            assert!(sessions.configure_gate(&config).await.is_err());
        }
    }
    #[tokio::test]
    async fn three_live_executions_pass_min_three_but_two_do_not() {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        let dir = tempfile::TempDir::new().unwrap();
        let socket = dir.path().join("range.sock");
        let listener = pa_types::platform::transport::bind_transport(&socket)
            .await
            .unwrap();
        let sessions = SupervisorChildSessions::new(
            Arc::new(crate::supervisor_link::SupervisorLink::new(socket)),
            dir.path().into(),
            "parent".into(),
            Arc::new(crate::model_allowlist::ModelRefusalTelemetry::new(
                dir.path().into(),
                true,
            )),
        );
        let active = Arc::new(std::sync::atomic::AtomicUsize::new(3));
        let active_server = active.clone();
        tokio::spawn(async move {
            loop {
                let stream = listener.accept().await.unwrap();
                let active = active_server.clone();
                tokio::spawn(async move {
                    let (reader, mut writer) = stream.split();
                    writer.write_all(b"{\"type\":\"daemon_hello\",\"protocol\":{\"name\":\"prime-agent.daemon\",\"version\":7}}\n").await.unwrap();
                    let mut reader = BufReader::new(reader);
                    loop {
                        let mut line = String::new();
                        if reader.read_line(&mut line).await.unwrap() == 0 {
                            return;
                        }
                        let request: Value = serde_json::from_str(&line).unwrap();
                        let index = request["command"]["activeSessionId"]
                            .as_str()
                            .unwrap()
                            .strip_prefix("kid-")
                            .unwrap()
                            .parse::<usize>()
                            .unwrap();
                        let executing = index < active.load(std::sync::atomic::Ordering::SeqCst);
                        let state = json!({"workerInstanceId":"worker","ownExecutionStarted":executing,"isStreaming":executing,"runningMessageIds":["message"],"sessionActions":{"queuedCount":0}});
                        let response = crate::protocol::response_success(
                            request["id"].as_str(),
                            "get_state",
                            Some(state),
                        );
                        if writer
                            .write_all(
                                format!("{}\n", serde_json::to_string(&response).unwrap())
                                    .as_bytes(),
                            )
                            .await
                            .is_err()
                        {
                            return;
                        }
                    }
                });
            }
        });
        let mut config = configure(2);
        config["policy"]["minActive"] = json!(3);
        config["policy"]["maxActive"] = json!(8);
        sessions.configure_gate(&config).await.unwrap();
        let mut assignments = Vec::new();
        for i in 0..3 {
            let id = format!("kid-{i}");
            sessions
                .push_test_child(RlmChildIdentity {
                    rlm_child_id: id.clone(),
                    active_session_id: id.clone(),
                    session_id: None,
                    session_name: id.clone(),
                })
                .await;
            let record = sessions.inner.find_record(&id).await.unwrap();
            {
                let mut row = record.lock().await;
                row.admission_generation = Some("generation".into());
                row.expected_message_id = Some("message".into());
            }
            assignments.push(json!({"childId":id,"admissionGeneration":"generation","incarnation":"worker","assignmentId":format!("assignment-{i}"),"taskGeneration":1,"ownership":format!("lane-{i}"),"acceptanceRef":"accept","artifactRef":"artifact","dependenciesSatisfied":true}));
        }
        config["expectedRevision"] = json!(1);
        config["assignments"] = json!(assignments);
        let status = sessions.configure_gate(&config).await.unwrap();
        assert_eq!(status["knownActive"], 3);
        assert_eq!(status["decision"], "pass");
        active.store(2, std::sync::atomic::Ordering::SeqCst);
        let status = sessions.gate_status().await;
        assert_eq!(status["knownActive"], 2);
        assert_eq!(status["decision"], "corrective");
    }
}
