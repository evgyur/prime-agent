//! The controller test battery: family roster, direct peer delivery,
//! fallback, and observe families.

use super::observe::summaries_from_roster;
use super::*;
use crate::protocol::{response_failure, response_success};
use crate::rlm_children::RlmChildIdentity;
use crate::supervisor_link::SupervisorLink;
use pa_core::session_engine::agent_messaging::AgentMessageController;
use pa_types::platform::transport::bind_transport;
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

/// A scripted JSONL supervisor: answers `list` with a roster,
/// `get_worker_peer_transport` per script, and `send_message` with a
/// TS receipt.
async fn spawn_fake_supervisor(
    socket: std::path::PathBuf,
    roster: Value,
    ticket_response: Option<Value>,
) {
    let listener = bind_transport(&socket).await.unwrap();
    tokio::spawn(async move {
        loop {
            let Ok(stream) = listener.accept().await else {
                return;
            };
            let roster = roster.clone();
            let ticket_response = ticket_response.clone();
            tokio::spawn(async move {
                let (reader, mut writer) = stream.split();
                let mut reader = BufReader::new(reader);
                writer
                    .write_all(
                        b"{\"type\":\"daemon_hello\",\"protocol\":{\"name\":\"prime-agent.daemon\",\"version\":7}}\n",
                    )
                    .await
                    .unwrap();
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).await.unwrap() == 0 {
                        return;
                    }
                    let value: Value = serde_json::from_str(line.trim()).unwrap();
                    let id = value["id"].as_str().unwrap_or_default().to_string();
                    let command = value["command"].clone();
                    let command_type = command["type"].as_str().unwrap_or_default().to_string();
                    let response = match command_type.as_str() {
                        "list_agent_peers" => response_success(
                            Some(&id),
                            "list_agent_peers",
                            Some(json!({ "peers": roster["sessions"] })),
                        ),
                        "get_worker_peer_transport" => match ticket_response.clone() {
                            Some(ticket) => {
                                response_success(Some(&id), &command_type, Some(ticket))
                            }
                            None => response_failure(
                                Some(&id),
                                &command_type,
                                "Session worker does not support direct peer transport",
                                None,
                            ),
                        },
                        "send_message" => response_success(
                            Some(&id),
                            "send_message",
                            Some(json!({
                                "id": "agentmsg_direct",
                                "source": "agent_message",
                                "target": {
                                    "activeSessionId": "bbb222",
                                    "sessionId": "sess-b",
                                    "runtimeKind": "top-level",
                                },
                                "message": command["message"].clone(),
                                "deliveryStatus": "delivered",
                                "deliveredAt": "2026-01-01T00:00:00.000Z",
                                "deliveryMode": "steer",
                            })),
                        ),
                        other => response_failure(Some(&id), other, "unexpected command", None),
                    };
                    let mut line = serde_json::to_string(&response).unwrap();
                    line.push('\n');
                    if writer.write_all(line.as_bytes()).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
}

fn controller(
    socket: std::path::PathBuf,
    own_summary: Option<Value>,
) -> LinkAgentMessageController {
    LinkAgentMessageController {
        link: Arc::new(SupervisorLink::new(socket)),
        active_session_id: "aaa111".to_string(),
        worker_token: "tok-a".to_string(),
        own_summary: Arc::new(std::sync::Mutex::new(own_summary)),
        children: None,
    }
}

/// A controller whose children registry holds one resident child: the same
/// registry shape `rlm.list_subagents` reads.
fn controller_with_children(
    socket: std::path::PathBuf,
    own_summary: Option<Value>,
) -> LinkAgentMessageController {
    let children = crate::rlm_children::SupervisorChildSessions::new(
        Arc::new(SupervisorLink::new(socket.clone())),
        std::path::PathBuf::from("/agent"),
        "aaa111".to_string(),
        std::sync::Arc::new(crate::model_allowlist::ModelRefusalTelemetry::new(
            std::path::PathBuf::from("/agent"),
            /*telemetry_disabled*/ true,
        )),
    );
    let mut controller = controller(socket, own_summary);
    controller.children = Some(Arc::new(children));
    controller
}

/// Seed the children registry with one admitted child (the same state
/// `rlm.spawn` leaves behind, without the supervisor round trip).
async fn admit_child(controller: &LinkAgentMessageController, child: RlmChildIdentity) {
    controller
        .children
        .as_ref()
        .expect("children registry")
        .push_test_child(child)
        .await;
}

fn own_summary() -> Option<Value> {
    Some(json!({
        "activeSessionId": "aaa111",
        "sessionId": "sess-a",
        "sessionName": "alpha",
        "runtimeKind": "top-level",
    }))
}

/// The observe roster reduced to what the family classifiers decide:
/// each listed row's live id and relationship, in roster order.
fn labeled(
    sessions: Vec<Value>,
    identity: &FamilyIdentity,
) -> Vec<(Option<String>, Option<AgentFamilyRelationship>)> {
    summaries_from_roster(sessions, identity, &[])
        .into_iter()
        .map(|summary| (summary.active_session_id, summary.relationship))
        .collect()
}

fn input() -> AgentMessageSendInput {
    AgentMessageSendInput {
        target: "bbb222".to_string(),
        message: "hello there".to_string(),
        receiver_role: Some(AgentFamilyRelationship::Sibling),
    }
}

/// Follow-up admissions through the real controller, with a retained first
/// task completed through the real collect consumer before each delivery.
#[derive(Clone, Copy)]
enum RetaskAdmission {
    Queued,
    Rejected,
    LostAck,
    MalformedAck,
    CancelAfterSend,
    FastFinish,
}

async fn retask_controller_fixture(
    admission: RetaskAdmission,
) -> (
    tempfile::TempDir,
    LinkAgentMessageController,
    Arc<std::sync::atomic::AtomicUsize>,
) {
    let dir = tempfile::TempDir::new().unwrap();
    let socket = dir.path().join("retask.sock");
    let listener = bind_transport(&socket).await.unwrap();
    let busy = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let answer = Arc::new(std::sync::Mutex::new("FIRST".to_string()));
    let sends = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let send_count = Arc::clone(&sends);
    let child_registry = Arc::new(std::sync::Mutex::new(
        None::<Arc<crate::rlm_children::SupervisorChildSessions>>,
    ));
    let reply_registry = Arc::clone(&child_registry);
    tokio::spawn(async move {
        loop {
            let Ok(stream) = listener.accept().await else {
                return;
            };
            let busy = Arc::clone(&busy);
            let answer = Arc::clone(&answer);
            let sends = Arc::clone(&send_count);
            let reply_registry = Arc::clone(&reply_registry);
            tokio::spawn(async move {
                let (reader, mut writer) = stream.split();
                let mut reader = BufReader::new(reader);
                writer
                    .write_all(b"{\"type\":\"daemon_hello\"}\n")
                    .await
                    .unwrap();
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).await.unwrap() == 0 {
                        return;
                    }
                    let value: Value = serde_json::from_str(&line).unwrap();
                    let id = value["id"].as_str().unwrap();
                    let command = &value["command"];
                    let kind = command["type"].as_str().unwrap();
                    let response = match kind {
                        "get_worker_peer_transport" => {
                            response_failure(Some(id), kind, "no peer", None)
                        }
                        "get_state" => response_success(
                            Some(id),
                            kind,
                            Some(json!({
                                "isStreaming": false,
                                "sessionActions": { "queuedCount": usize::from(busy.load(std::sync::atomic::Ordering::SeqCst)) }
                            })),
                        ),
                        "get_last_assistant_text" => response_success(
                            Some(id),
                            kind,
                            Some(json!({
                                "text": answer.lock().unwrap().clone()
                            })),
                        ),
                        "wait_for_idle" => {
                            if busy.load(std::sync::atomic::Ordering::SeqCst) {
                                std::future::pending::<()>().await;
                            }
                            response_success(Some(id), kind, None)
                        }
                        "send_message" => {
                            sends.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            match admission {
                                RetaskAdmission::Rejected => {
                                    response_failure(Some(id), kind, "admission rejected", None)
                                }
                                RetaskAdmission::LostAck => {
                                    busy.store(true, std::sync::atomic::Ordering::SeqCst);
                                    return;
                                }
                                RetaskAdmission::MalformedAck => {
                                    busy.store(true, std::sync::atomic::Ordering::SeqCst);
                                    response_success(
                                        Some(id),
                                        kind,
                                        Some(json!({ "invalid": true })),
                                    )
                                }
                                RetaskAdmission::CancelAfterSend => {
                                    busy.store(true, std::sync::atomic::Ordering::SeqCst);
                                    std::future::pending::<()>().await;
                                    unreachable!("delivery acknowledgement is gated forever");
                                }
                                RetaskAdmission::Queued | RetaskAdmission::FastFinish => {
                                    let fast = matches!(admission, RetaskAdmission::FastFinish);
                                    busy.store(!fast, std::sync::atomic::Ordering::SeqCst);
                                    if fast {
                                        *answer.lock().unwrap() = "SECOND".to_string();
                                        let registry =
                                            reply_registry.lock().unwrap().clone().unwrap();
                                        registry.mark_replied("bbb222").await;
                                    }
                                    response_success(
                                        Some(id),
                                        kind,
                                        Some(json!({
                                            "id": "retask-receipt", "target": { "activeSessionId": "bbb222", "sessionId": "sess-b" },
                                            "deliveryStatus": if fast { "delivered" } else { "queued" },
                                            "message": command["message"]
                                        })),
                                    )
                                }
                            }
                        }
                        other => response_failure(Some(id), other, "unexpected command", None),
                    };
                    let mut encoded = serde_json::to_string(&response).unwrap();
                    encoded.push('\n');
                    if writer.write_all(encoded.as_bytes()).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    let controller = controller_with_children(socket, own_summary());
    *child_registry.lock().unwrap() = controller.children.clone();
    admit_child(
        &controller,
        RlmChildIdentity {
            rlm_child_id: "sub-retask".to_string(),
            active_session_id: "bbb222".to_string(),
            session_id: Some("sess-b".to_string()),
            session_name: "retask-child".to_string(),
        },
    )
    .await;
    let children = controller.children.as_ref().unwrap();
    children
        .prepare_admission_display_for_test("sub-retask", &dir.path().join("child"))
        .await;
    let first = pa_core::session_engine::rlm_host::RlmSubagentHost::collect(
        children.as_ref(),
        vec!["sub-retask".to_string()],
        100,
    )
    .await
    .unwrap();
    assert_eq!(first[0].status, "done");
    assert_eq!(first[0].answer_text.as_deref(), Some("FIRST"));
    (dir, controller, sends)
}

#[tokio::test]
async fn retask_controller_display_write_failure_prevents_send() {
    let (dir, controller, sends) = retask_controller_fixture(RetaskAdmission::Queued).await;
    let display = dir.path().join("child/rlm-subagent.json");
    use std::os::unix::fs::PermissionsExt;
    let child_dir = display.parent().unwrap();
    std::fs::set_permissions(child_dir, std::fs::Permissions::from_mode(0o500)).unwrap();
    let result = controller.send_agent_message(input()).await;
    std::fs::set_permissions(child_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(result.is_err());
    assert_eq!(sends.load(std::sync::atomic::Ordering::SeqCst), 0);
    let current = pa_core::session_engine::rlm_host::RlmSubagentHost::collect(
        controller.children.as_ref().unwrap().as_ref(),
        vec!["sub-retask".into()],
        0,
    )
    .await
    .unwrap();
    assert_eq!(current[0].answer_text.as_deref(), Some("FIRST"));
    assert!(current[0].settled);
}

#[tokio::test]
async fn retask_controller_identity_mismatch_prevents_send() {
    let (dir, controller, sends) = retask_controller_fixture(RetaskAdmission::Queued).await;
    let mut display =
        crate::rlm_ledger::read_rlm_subagent_display(&dir.path().join("child")).unwrap();
    display.child_id = "foreign-child".into();
    crate::rlm_ledger::write_rlm_subagent_display(&display).unwrap();
    assert!(controller.send_agent_message(input()).await.is_err());
    assert_eq!(sends.load(std::sync::atomic::Ordering::SeqCst), 0);
}

#[tokio::test]
async fn retask_controller_qualified_settle_clears_marker() {
    let (dir, controller, _) = retask_controller_fixture(RetaskAdmission::FastFinish).await;
    let children = controller.children.as_ref().unwrap();
    let settled = children.settle_notified();
    controller.send_agent_message(input()).await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), settled)
        .await
        .unwrap();
    let display = crate::rlm_ledger::read_rlm_subagent_display(&dir.path().join("child")).unwrap();
    assert_eq!(display.admission_unresolved, None);
    assert_eq!(display.status, "completed");
}

#[tokio::test]
async fn retask_controller_tombstone_prevents_send() {
    let (dir, controller, sends) = retask_controller_fixture(RetaskAdmission::Queued).await;
    let mut display =
        crate::rlm_ledger::read_rlm_subagent_display(&dir.path().join("child")).unwrap();
    display.status = "deleted".into();
    crate::rlm_ledger::write_rlm_subagent_display(&display).unwrap();
    assert!(controller.send_agent_message(input()).await.is_err());
    assert_eq!(sends.load(std::sync::atomic::Ordering::SeqCst), 0);
}

#[tokio::test]
async fn retask_controller_queued_admission_invalidates_prior_completion() {
    let (_dir, controller, sends) = retask_controller_fixture(RetaskAdmission::Queued).await;
    controller.send_agent_message(input()).await.unwrap();
    let children = controller.children.as_ref().unwrap();
    let result = pa_core::session_engine::rlm_host::RlmSubagentHost::collect(
        children.as_ref(),
        vec!["sub-retask".to_string()],
        0,
    )
    .await
    .unwrap();
    assert_eq!(sends.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(result[0].status, "running");
    assert!(!result[0].settled);
    assert_eq!(result[0].answer_text, None);
}

#[tokio::test]
async fn retask_controller_rejected_admission_preserves_prior_completion() {
    let (dir, controller, sends) = retask_controller_fixture(RetaskAdmission::Rejected).await;
    assert!(controller.send_agent_message(input()).await.is_err());
    let children = controller.children.as_ref().unwrap();
    let result = pa_core::session_engine::rlm_host::RlmSubagentHost::collect(
        children.as_ref(),
        vec!["sub-retask".to_string()],
        0,
    )
    .await
    .unwrap();
    assert_eq!(sends.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(result[0].status, "done");
    assert_eq!(result[0].answer_text.as_deref(), Some("FIRST"));
    assert_eq!(
        crate::rlm_ledger::read_rlm_subagent_display(&dir.path().join("child"))
            .unwrap()
            .admission_unresolved,
        None
    );
}

#[tokio::test]
async fn retask_controller_lost_ack_is_not_retried_or_reported_as_prior_completion() {
    let (dir, controller, sends) = retask_controller_fixture(RetaskAdmission::LostAck).await;
    assert!(controller.send_agent_message(input()).await.is_err());
    let children = controller.children.as_ref().unwrap();
    let result = pa_core::session_engine::rlm_host::RlmSubagentHost::collect(
        children.as_ref(),
        vec!["sub-retask".to_string()],
        0,
    )
    .await
    .unwrap();
    assert_eq!(
        sends.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "ambiguous send must not repeat"
    );
    assert!(
        !result[0].settled,
        "lost acknowledgement leaves new work owed"
    );
    assert_eq!(result[0].answer_text, None);
    assert_eq!(
        crate::rlm_ledger::read_rlm_subagent_display(&dir.path().join("child"))
            .unwrap()
            .admission_unresolved,
        Some(true)
    );
}

#[tokio::test]
async fn retask_controller_fast_finish_captures_new_answer_without_busy_edge() {
    let (_dir, controller, sends) = retask_controller_fixture(RetaskAdmission::FastFinish).await;
    controller.send_agent_message(input()).await.unwrap();
    let children = controller.children.as_ref().unwrap();
    assert!(
        children.child_replied_for_test("bbb222").await,
        "reply callback before receipt must survive accepted admission"
    );
    let result = pa_core::session_engine::rlm_host::RlmSubagentHost::collect(
        children.as_ref(),
        vec!["sub-retask".to_string()],
        100,
    )
    .await
    .unwrap();
    assert_eq!(sends.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(result[0].answer_text.as_deref(), Some("SECOND"));
}

#[tokio::test]
async fn retask_controller_malformed_ack_does_not_restore_prior_completion() {
    let (_dir, controller, sends) = retask_controller_fixture(RetaskAdmission::MalformedAck).await;
    assert!(controller.send_agent_message(input()).await.is_err());
    let children = controller.children.as_ref().unwrap();
    let result = pa_core::session_engine::rlm_host::RlmSubagentHost::collect(
        children.as_ref(),
        vec!["sub-retask".to_string()],
        10,
    )
    .await
    .unwrap();
    assert_eq!(sends.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert!(!result[0].settled);
    assert_eq!(result[0].answer_text, None);
}

#[tokio::test]
async fn retask_controller_cancel_after_send_keeps_work_unresolved() {
    let (dir, controller, sends) =
        retask_controller_fixture(RetaskAdmission::CancelAfterSend).await;
    let mut send = Box::pin(controller.send_agent_message(input()));
    // Poll the actual send until the fake has received its command; no timer
    // infers admission and the acknowledgement is never released.
    std::future::poll_fn(|cx| {
        assert!(std::future::Future::poll(send.as_mut(), cx).is_pending());
        if sends.load(std::sync::atomic::Ordering::SeqCst) == 1 {
            std::task::Poll::Ready(())
        } else {
            cx.waker().wake_by_ref();
            std::task::Poll::Pending
        }
    })
    .await;
    drop(send);
    let children = controller.children.as_ref().unwrap();
    let result = pa_core::session_engine::rlm_host::RlmSubagentHost::collect(
        children.as_ref(),
        vec!["sub-retask".to_string()],
        10,
    )
    .await
    .unwrap();
    assert_eq!(sends.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert!(!result[0].settled);
    assert_eq!(result[0].answer_text, None);
    assert_eq!(
        crate::rlm_ledger::read_rlm_subagent_display(&dir.path().join("child"))
            .unwrap()
            .admission_unresolved,
        Some(true)
    );
}

#[tokio::test]
async fn family_reads_siblings_from_the_supervisor_roster() {
    let dir = tempfile::TempDir::new().unwrap();
    let socket = dir.path().join("sup.sock");
    spawn_fake_supervisor(
        socket.clone(),
        json!({ "sessions": [
            { "activeSessionId": "aaa111", "sessionId": "sess-a", "sessionName": "alpha" },
            { "activeSessionId": "bbb222", "sessionId": "sess-b", "sessionName": "beta" },
            { "activeSessionId": "ccc333", "sessionId": "sess-c" },
        ]}),
        None,
    )
    .await;
    let controller = controller(socket, None);
    let family = controller.family().await.unwrap();
    assert_eq!(family.len(), 2, "{family:?}");
    assert_eq!(family[0].relationship, AgentFamilyRelationship::Sibling);
    assert_eq!(family[0].id, "bbb222");
    assert_eq!(family[0].name.as_deref(), Some("beta"));
    assert_eq!(family[1].id, "ccc333");
    assert_eq!(family[1].name, None);
}

#[tokio::test]
async fn family_labels_children_and_parent_from_the_registry() {
    let dir = tempfile::TempDir::new().unwrap();
    let socket = dir.path().join("sup.sock");
    spawn_fake_supervisor(
        socket.clone(),
        json!({ "sessions": [
            { "activeSessionId": "aaa111", "sessionId": "sess-a", "sessionName": "alpha" },
            { "activeSessionId": "bbb222", "sessionId": "sess-b", "sessionName": "beta",
              "parentActiveSessionId": "ppp000", "parentSessionId": "sess-p",
              "runtimeKind": "subagent" },
            { "activeSessionId": "ddd444", "sessionId": "sess-d", "sessionName": "worker-a" },
            { "activeSessionId": "ppp000", "sessionId": "sess-p", "sessionName": "papa" },
            { "activeSessionId": "xxx999", "sessionId": "sess-x", "sessionName": "beta",
              "runtimeKind": "top-level" },
        ]}),
        None,
    )
    .await;
    let own_summary = Some(json!({
        "activeSessionId": "aaa111",
        "sessionId": "sess-a",
        "sessionName": "alpha",
        "parentActiveSessionId": "ppp000",
        "parentSessionId": "sess-p",
    }));
    let controller = controller_with_children(socket, own_summary);
    admit_child(
        &controller,
        RlmChildIdentity {
            rlm_child_id: "sub-kid1".to_string(),
            active_session_id: "ddd444".to_string(),
            session_id: Some("sess-d".to_string()),
            session_name: "worker-a".to_string(),
        },
    )
    .await;
    let family = controller.family().await.unwrap();
    // TS `selectAgentFamily` order: parent, siblings, children.
    assert_eq!(family.len(), 3, "{family:?}");
    assert_eq!(family[0].relationship, AgentFamilyRelationship::Parent);
    assert_eq!(family[0].id, "ppp000");
    assert_eq!(family[0].name.as_deref(), Some("papa"));
    assert_eq!(family[1].relationship, AgentFamilyRelationship::Sibling);
    assert_eq!(family[1].id, "bbb222");
    assert_eq!(
        family[2].relationship,
        AgentFamilyRelationship::Child,
        "{family:?}"
    );
    assert_eq!(family[2].id, "ddd444");
    assert_eq!(family[2].name.as_deref(), Some("worker-a"));
    assert_eq!(family[2].aliases, vec!["sub-kid1", "sess-d"]);
    assert!(!family
        .iter()
        .any(|member| member.id == "ddd444"
            && member.relationship == AgentFamilyRelationship::Sibling));
    assert!(!family.iter().any(|member| member.id == "xxx999"));
}

#[tokio::test]
async fn family_resolves_the_parent_by_session_id() {
    let dir = tempfile::TempDir::new().unwrap();
    let socket = dir.path().join("sup.sock");
    spawn_fake_supervisor(
        socket.clone(),
        json!({ "sessions": [
            { "activeSessionId": "aaa111", "sessionId": "sess-a" },
            { "activeSessionId": "rrr777", "sessionId": "sess-p", "sessionName": "papa" },
        ]}),
        None,
    )
    .await;
    let own_summary = Some(json!({
        "activeSessionId": "aaa111",
        "sessionId": "sess-a",
        "parentActiveSessionId": "stale-parent",
        "parentSessionId": "sess-p",
    }));
    let controller = controller(socket, own_summary);
    let family = controller.family().await.unwrap();
    assert_eq!(family.len(), 1, "{family:?}");
    assert_eq!(family[0].relationship, AgentFamilyRelationship::Parent);
    assert_eq!(family[0].id, "rrr777");
}

/// Registry children the roster does not list stay addressable as Child
/// members keyed by their durable session id (the wake-resolvable
/// selector), the spawn-time live id kept as an alias.
#[tokio::test]
async fn family_keeps_off_roster_children_addressable() {
    let dir = tempfile::TempDir::new().unwrap();
    let socket = dir.path().join("sup.sock");
    spawn_fake_supervisor(
        socket.clone(),
        json!({ "sessions": [
            { "activeSessionId": "aaa111", "sessionId": "sess-a" },
        ]}),
        None,
    )
    .await;
    let controller = controller_with_children(socket, None);
    admit_child(
        &controller,
        RlmChildIdentity {
            rlm_child_id: "sub-kid2".to_string(),
            active_session_id: "eee555".to_string(),
            session_id: Some("sess-e".to_string()),
            session_name: "worker-b".to_string(),
        },
    )
    .await;
    let family = controller.family().await.unwrap();
    assert_eq!(family.len(), 1, "{family:?}");
    assert_eq!(family[0].relationship, AgentFamilyRelationship::Child);
    assert_eq!(family[0].id, "sess-e");
    assert_eq!(family[0].name.as_deref(), Some("worker-b"));
    assert_eq!(family[0].aliases, vec!["sub-kid2", "sess-e", "eee555"]);
}

#[tokio::test]
async fn refused_ticket_falls_back_to_the_supervisor_route() {
    let dir = tempfile::TempDir::new().unwrap();
    let socket = dir.path().join("sup.sock");
    spawn_fake_supervisor(socket.clone(), json!({ "sessions": [] }), None).await;
    let controller = controller(socket, own_summary());
    let receipt = controller.send_agent_message(input()).await.unwrap();
    assert_eq!(receipt.id, "agentmsg_direct");
    assert_eq!(receipt.target, "bbb222");
    assert_eq!(receipt.target_session_id.as_deref(), Some("sess-b"));
    assert_eq!(
        receipt.delivery_status,
        AgentMessageDeliveryStatus::Delivered
    );
    assert_eq!(receipt.message, "hello there");
    assert_eq!(
        receipt.receiver_role,
        Some(AgentFamilyRelationship::Sibling)
    );
}

#[tokio::test]
async fn self_target_is_refused() {
    let controller = controller(std::path::PathBuf::from("/nonexistent.sock"), None);
    let error = controller
        .send_agent_message(AgentMessageSendInput {
            target: "aaa111".to_string(),
            message: "note to self".to_string(),
            receiver_role: None,
        })
        .await
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "Agent messaging cannot target the sending session"
    );
}

/// A minted ticket delivers straight to the target worker's socket,
/// addressed to the ticket's resolved session: `peer_auth` with the
/// worker purpose, then `worker_deliver_message` carrying the TS
/// sender identity block, and the receipt maps onto the kernel shape.
#[tokio::test]
async fn direct_ticket_delivers_to_the_target_worker_socket() {
    let dir = tempfile::TempDir::new().unwrap();
    let worker_socket = dir.path().join("worker.sock");
    let listener = bind_transport(&worker_socket).await.unwrap();
    let received = Arc::new(std::sync::Mutex::new(Vec::<(String, Value)>::new()));
    let recorded = Arc::clone(&received);
    tokio::spawn(async move {
        let stream = listener.accept().await.unwrap();
        let (reader, mut writer) = stream.split();
        let mut reader = crate::framing::PrivateFrameReader::new(
            reader,
            crate::framing::DEFAULT_PRIVATE_FRAME_LIMITS,
        );
        let hello = crate::framing::encode_private_frame(
            &json!({ "kind": "outbound", "outboundType": "daemon_hello" }),
            b"{}".as_slice(),
            crate::framing::DEFAULT_PRIVATE_FRAME_LIMITS,
        )
        .unwrap();
        writer.write_all(&hello).await.unwrap();
        loop {
            let Some(frame) = reader.read_frame().await.unwrap() else {
                return;
            };
            let command_type = frame
                .header
                .get("commandType")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let request_id = frame
                .header
                .get("requestId")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let payload: Value = serde_json::from_slice(&frame.payload).unwrap();
            recorded
                .lock()
                .unwrap()
                .push((command_type.clone(), payload.clone()));
            let response = match command_type.as_str() {
                "peer_auth" => response_success(
                    Some(&request_id),
                    "peer_auth",
                    Some(json!({
                        "workerInstanceId": "inst-b",
                        "activeSessionId": "bbb222",
                        "purpose": "worker",
                    })),
                ),
                "worker_deliver_message" => response_success(
                    Some(&request_id),
                    "worker_deliver_message",
                    Some(json!({
                        "id": "agentmsg_peer",
                        "source": "agent_message",
                        "target": {
                            "activeSessionId": "bbb222",
                            "sessionId": "sess-b",
                            "sessionName": "beta",
                            "runtimeKind": "top-level",
                        },
                        "message": payload["message"].clone(),
                        "deliveryStatus": "queued",
                        "queuedAt": "2026-01-01T00:00:00.000Z",
                        "deliveryMode": "steer",
                    })),
                ),
                other => response_failure(Some(&request_id), other, "unexpected", None),
            };
            let frame = crate::framing::encode_private_frame(
                &json!({
                    "kind": "outbound",
                    "requestId": request_id,
                    "outboundType": "response",
                }),
                &serde_json::to_vec(&response).unwrap(),
                crate::framing::DEFAULT_PRIVATE_FRAME_LIMITS,
            )
            .unwrap();
            writer.write_all(&frame).await.unwrap();
        }
    });

    let ticket = json!({
        "purpose": "worker",
        "socketPath": worker_socket.to_string_lossy(),
        "socketIdentity": { "dev": 1, "ino": 1 },
        "workerInstanceId": "inst-b",
        "activeSessionId": "bbb222",
        "grantId": "g1",
        "token": "secret",
        "expiresAt": "2026-01-01T00:00:30.000Z",
    });
    let socket = dir.path().join("sup.sock");
    spawn_fake_supervisor(socket.clone(), json!({ "sessions": [] }), Some(ticket)).await;
    let controller = controller(socket, own_summary());
    // The supervisor resolved the durable selector "sess-b" into the ticket.
    let receipt = controller
        .send_agent_message(AgentMessageSendInput {
            target: "sess-b".to_string(),
            ..input()
        })
        .await
        .unwrap();
    assert_eq!(receipt.id, "agentmsg_peer");
    assert_eq!(receipt.delivery_status, AgentMessageDeliveryStatus::Queued);
    assert_eq!(receipt.target, "bbb222");
    assert_eq!(receipt.target_session_name.as_deref(), Some("beta"));

    // The wire saw the exact two commands with the TS shapes.
    let received = received.lock().unwrap().clone();
    assert_eq!(received.len(), 2, "{received:?}");
    assert_eq!(received[0].0, "peer_auth");
    assert_eq!(received[0].1["purpose"], "worker");
    assert_eq!(received[0].1["grantId"], "g1");
    assert_eq!(received[1].0, "worker_deliver_message");
    let delivery = &received[1].1;
    assert_eq!(delivery["targetActiveSessionId"], "bbb222");
    assert_eq!(delivery["message"], "hello there");
    // TS sender identity block: endpoint fields plus the agent client id.
    assert_eq!(delivery["sender"]["activeSessionId"], "aaa111");
    assert_eq!(delivery["sender"]["sessionId"], "sess-a");
    assert_eq!(delivery["sender"]["sessionName"], "alpha");
    assert_eq!(delivery["sender"]["runtimeKind"], "top-level");
    assert_eq!(delivery["sender"]["clientId"], "agent");
}

#[test]
fn same_session_file_resolves_the_storage_root_alias() {
    assert!(same_session_file(
        "/agent/sessions/01a0d0a5-e954-71b7-8479-8dc7980768a1.jsonl",
        "/agent/sessions/01a0d0a5-e954-71b7-8479-8dc7980768a1.jsonl",
    ));
    assert!(same_session_file(
        "/old-agent-root/sessions/01a0d0a5-e954-71b7-8479-8dc7980768a1.jsonl",
        "/agent/session-artifacts/sess-p/sub-1/01a0d0a5-e954-71b7-8479-8dc7980768a1.jsonl",
    ));
    assert!(!same_session_file(
        "/agent/sessions/01a0d0a5-e954-71b7-8479-8dc7980768a1.jsonl",
        "/agent/sessions/21b1e1b6-f065-4288-9fa0-9ec8980768a2.jsonl",
    ));
    // The durable id is uuid-shaped: a shared NON-uuid stem (arbitrary
    // create-provided sessionPath values) never aliases across families.
    assert!(!same_session_file(
        "/project-a/session.jsonl",
        "/project-b/session.jsonl",
    ));
}

#[test]
fn summaries_label_the_nuclear_family_by_durable_edges() {
    let identity = FamilyIdentity {
        active_session_id: "kid111".to_string(),
        session_id: Some("sess-kid".to_string()),
        session_file: Some("/agent/session-artifacts/sess-p/sub-2/sess-kid.jsonl".to_string()),
        parent_active_session_id: Some("ppp000".to_string()),
        parent_session_id: Some("sess-p".to_string()),
        parent_session_path: Some("/agent/sessions/sess-p.jsonl".to_string()),
        rlm_depth: 1,
    };
    let sessions = vec![
        json!({
            "activeSessionId": "kid111", "sessionId": "sess-kid",
            "sessionName": "self", "runtimeKind": "subagent", "activity": "idle",
        }),
        json!({
            "activeSessionId": "ppp000", "sessionId": "sess-p",
            "sessionName": "papa", "runtimeKind": "top-level", "activity": "idle",
        }),
        json!({
            "activeSessionId": "sib222", "sessionId": "sess-sib",
            "sessionName": "sibling", "runtimeKind": "subagent", "activity": "working",
            "parentActiveSessionId": "ppp000", "parentSessionId": "sess-p",
        }),
        json!({
            "activeSessionId": "own333", "sessionId": "sess-own",
            "sessionName": "own-child", "runtimeKind": "subagent", "activity": "idle",
            "parentActiveSessionId": "kid111", "parentSessionId": "sess-kid",
        }),
        json!({
            "activeSessionId": "foreign444", "sessionId": "sess-foreign",
            "sessionName": "survey-stream-route", "runtimeKind": "subagent",
            "parentActiveSessionId": "other999", "parentSessionId": "sess-other",
        }),
        json!({
            "activeSessionId": "root555", "sessionId": "sess-root",
            "sessionName": "another-root", "runtimeKind": "top-level",
        }),
    ];
    let summaries = summaries_from_roster(sessions, &identity, &[]);
    assert_eq!(summaries.len(), 4, "{summaries:?}");
    let current = summaries.iter().find(|s| s.is_current).unwrap();
    assert_eq!(current.active_session_id.as_deref(), Some("kid111"));
    assert_eq!(current.relationship, None);
    let parent = summaries
        .iter()
        .find(|s| s.active_session_id.as_deref() == Some("ppp000"))
        .unwrap();
    assert_eq!(parent.relationship, Some(AgentFamilyRelationship::Parent));
    let sibling = summaries
        .iter()
        .find(|s| s.active_session_id.as_deref() == Some("sib222"))
        .unwrap();
    assert_eq!(sibling.relationship, Some(AgentFamilyRelationship::Sibling));
    let child = summaries
        .iter()
        .find(|s| s.active_session_id.as_deref() == Some("own333"))
        .unwrap();
    assert_eq!(child.relationship, Some(AgentFamilyRelationship::Child));
    assert!(!summaries
        .iter()
        .any(|s| s.active_session_id.as_deref() == Some("foreign444")));
    assert!(!summaries
        .iter()
        .any(|s| s.active_session_id.as_deref() == Some("root555")));
}

#[test]
fn summaries_bind_a_child_one_level_down_and_leave_a_same_depth_fork_out() {
    let parent = FamilyIdentity {
        active_session_id: "ppp000".to_string(),
        session_id: Some("sess-p".to_string()),
        session_file: Some("/agent/sessions/sess-p.jsonl".to_string()),
        parent_session_path: Some("/agent/sessions/sess-r.jsonl".to_string()),
        rlm_depth: 1,
        ..Default::default()
    };
    let sessions = vec![
        json!({
            "activeSessionId": "ppp000", "sessionId": "sess-p",
            "runtimeKind": "top-level", "activity": "idle",
            "parentSessionPath": "/agent/sessions/sess-r.jsonl", "rlmDepth": 1,
        }),
        json!({
            "activeSessionId": "usr111", "sessionId": "sess-usr",
            "runtimeKind": "top-level", "activity": "working",
            "parentSessionPath": "/agent/sessions/sess-p.jsonl", "rlmDepth": 2,
        }),
        json!({
            "activeSessionId": "frk222", "sessionId": "sess-frk",
            "runtimeKind": "top-level", "activity": "working",
            "parentSessionPath": "/agent/sessions/sess-p.jsonl", "rlmDepth": 1,
        }),
    ];
    assert_eq!(
        labeled(sessions, &parent),
        vec![
            (Some("ppp000".to_string()), None),
            (
                Some("usr111".to_string()),
                Some(AgentFamilyRelationship::Child)
            ),
        ]
    );

    // From the user child's own view: a same-depth subagent of the same
    // parent is a Sibling; the fork one level up is outside the family.
    let user_child = FamilyIdentity {
        active_session_id: "usr111".to_string(),
        session_id: Some("sess-usr".to_string()),
        session_file: Some("/agent/sessions/sess-usr.jsonl".to_string()),
        parent_session_path: Some("/agent/sessions/sess-p.jsonl".to_string()),
        rlm_depth: 2,
        ..Default::default()
    };
    let sessions = vec![
        json!({
            "activeSessionId": "usr111", "sessionId": "sess-usr",
            "runtimeKind": "top-level", "activity": "working",
            "parentSessionPath": "/agent/sessions/sess-p.jsonl", "rlmDepth": 2,
        }),
        json!({
            "activeSessionId": "sub333", "sessionId": "sess-sub",
            "runtimeKind": "subagent", "activity": "idle",
            "parentSessionPath": "/agent/sessions/sess-p.jsonl", "rlmDepth": 2,
        }),
        json!({
            "activeSessionId": "frk222", "sessionId": "sess-frk",
            "runtimeKind": "top-level", "activity": "working",
            "parentSessionPath": "/agent/sessions/sess-p.jsonl", "rlmDepth": 1,
        }),
    ];
    assert_eq!(
        labeled(sessions, &user_child),
        vec![
            (Some("usr111".to_string()), None),
            (
                Some("sub333".to_string()),
                Some(AgentFamilyRelationship::Sibling)
            ),
        ]
    );
}

#[test]
fn summaries_treat_a_root_fork_as_a_root() {
    let parent = FamilyIdentity {
        active_session_id: "ppp000".to_string(),
        session_id: Some("sess-p".to_string()),
        session_file: Some("/agent/sessions/sess-p.jsonl".to_string()),
        ..Default::default()
    };
    let sessions = vec![
        json!({
            "activeSessionId": "ppp000", "sessionId": "sess-p",
            "sessionName": "papa", "runtimeKind": "top-level", "activity": "idle",
        }),
        json!({
            "activeSessionId": "usr111", "sessionId": "sess-usr",
            "sessionName": "user-child", "runtimeKind": "top-level",
            "activity": "working",
            "parentSessionPath": "/agent/sessions/sess-p.jsonl", "rlmDepth": 1,
        }),
        json!({
            "activeSessionId": "frk222", "sessionId": "sess-frk",
            "sessionName": "fork", "runtimeKind": "top-level",
            "activity": "working",
            "parentSessionPath": "/agent/sessions/sess-p.jsonl", "rlmDepth": 0,
        }),
    ];
    assert_eq!(
        labeled(sessions, &parent),
        vec![
            (Some("ppp000".to_string()), None),
            (
                Some("usr111".to_string()),
                Some(AgentFamilyRelationship::Child)
            ),
            (
                Some("frk222".to_string()),
                Some(AgentFamilyRelationship::Sibling)
            ),
        ]
    );

    // From the root fork's own view: its source and every other root are
    // Siblings, never a Parent.
    let fork = FamilyIdentity::from_summary(
        Some(&json!({
            "sessionId": "sess-frk",
            "sessionFile": "/agent/sessions/sess-frk.jsonl",
            "parentSessionPath": "/agent/sessions/sess-p.jsonl",
            "rlmDepth": 0,
        })),
        "frk222",
    );
    let sessions = vec![
        json!({
            "activeSessionId": "frk222", "sessionId": "sess-frk",
            "runtimeKind": "top-level", "activity": "idle",
            "parentSessionPath": "/agent/sessions/sess-p.jsonl", "rlmDepth": 0,
        }),
        json!({
            "activeSessionId": "ppp000", "sessionId": "sess-p",
            "sessionName": "papa", "runtimeKind": "top-level", "activity": "idle",
            "sessionFile": "/agent/sessions/sess-p.jsonl", "rlmDepth": 0,
        }),
        json!({
            "activeSessionId": "oth444", "sessionId": "sess-oth",
            "runtimeKind": "top-level", "activity": "idle", "rlmDepth": 0,
        }),
    ];
    assert_eq!(
        labeled(sessions, &fork),
        vec![
            (Some("frk222".to_string()), None),
            (
                Some("ppp000".to_string()),
                Some(AgentFamilyRelationship::Sibling)
            ),
            (
                Some("oth444".to_string()),
                Some(AgentFamilyRelationship::Sibling)
            ),
        ]
    );
}

/// TS #2493: observe rows carry the typed family status (the busy verdict) plus the
/// separate live activity axis — a quiet row is `idle`, never the pre-fix `inactive`.
#[test]
fn summaries_carry_the_typed_status_and_activity() {
    let identity = FamilyIdentity {
        active_session_id: "me000".to_string(),
        session_id: Some("sess-me".to_string()),
        session_file: Some("/agent/sessions/sess-me.jsonl".to_string()),
        parent_active_session_id: Some("ppp00".to_string()),
        parent_session_id: Some("sess-p".to_string()),
        parent_session_path: Some("/agent/sessions/sess-p.jsonl".to_string()),
        rlm_depth: 1,
    };
    let sessions = vec![
        // The current session streams a tool call: running, tool work.
        json!({
            "activeSessionId": "me000", "sessionId": "sess-me", "runtimeKind": "top-level",
            "activity": "working", "isStreaming": true, "isCompacting": false,
            "isSessionActive": true, "isRunningTools": true, "attachedClients": 1,
        }),
        // The parent sits quiet with a client attached: idle, a user.
        json!({
            "activeSessionId": "ppp00", "sessionId": "sess-p", "runtimeKind": "top-level",
            "activity": "idle", "isStreaming": false, "isCompacting": false,
            "isSessionActive": false, "isRunningTools": false, "attachedClients": 1,
        }),
        // A child mid-compaction: running, compacting.
        json!({
            "activeSessionId": "ch111", "sessionId": "sess-ch", "runtimeKind": "subagent",
            "activity": "working", "isStreaming": false, "isCompacting": true,
            "isSessionActive": true, "isRunningTools": false, "attachedClients": 0,
            "parentActiveSessionId": "me000", "parentSessionId": "sess-me",
        }),
        // A quiet child with no client: idle, idle.
        json!({
            "activeSessionId": "ch222", "sessionId": "sess-ch2", "runtimeKind": "subagent",
            "activity": "idle", "isStreaming": false, "isCompacting": false,
            "isSessionActive": false, "isRunningTools": false, "attachedClients": 0,
            "parentActiveSessionId": "me000", "parentSessionId": "sess-me",
        }),
        // A passivated ledger child: an INACTIVE family member, never a
        // live quiet session, and no activity axis.
        json!({
            "id": "ch333", "sessionId": "sess-ch3", "runtimeKind": "subagent",
            "activity": "idle", "isStreaming": false, "isCompacting": false,
            "isSessionActive": false, "isRunningTools": false, "attachedClients": 0,
            "parentActiveSessionId": "me000", "parentSessionId": "sess-me",
        }),
    ];
    let summaries = summaries_from_roster(sessions, &identity, &[]);
    assert_eq!(summaries.len(), 5, "{summaries:?}");
    let row = |id: &str| {
        summaries
            .iter()
            .find(|s| s.active_session_id.as_deref() == Some(id))
            .unwrap_or_else(|| panic!("missing row {id}: {summaries:?}"))
    };
    assert_eq!(row("me000").status, AgentFamilyStatus::Running);
    assert_eq!(row("me000").activity, Some(AgentObserveActivity::Tool));
    assert_eq!(row("ppp00").status, AgentFamilyStatus::Idle);
    assert_eq!(row("ppp00").activity, Some(AgentObserveActivity::User));
    assert_eq!(row("ch111").status, AgentFamilyStatus::Running);
    assert_eq!(
        row("ch111").activity,
        Some(AgentObserveActivity::Compacting)
    );
    assert_eq!(row("ch222").status, AgentFamilyStatus::Idle);
    assert_eq!(row("ch222").activity, Some(AgentObserveActivity::Idle));
    let passivated = summaries
        .iter()
        .find(|s| s.session_id == "sess-ch3")
        .expect("the passivated child stays an addressable family row");
    assert_eq!(passivated.status, AgentFamilyStatus::Inactive);
    assert_eq!(passivated.activity, None);
}

#[test]
fn summaries_label_root_siblings_and_never_foreign_children() {
    let identity = FamilyIdentity {
        active_session_id: "root111".to_string(),
        session_id: Some("sess-root".to_string()),
        session_file: Some("/agent/sessions/sess-root.jsonl".to_string()),
        ..Default::default()
    };
    let sessions = vec![
        json!({
            "activeSessionId": "root111", "sessionId": "sess-root",
            "runtimeKind": "top-level", "activity": "idle",
        }),
        json!({
            "activeSessionId": "root222", "sessionId": "sess-root2",
            "runtimeKind": "top-level", "activity": "idle",
        }),
        json!({
            "activeSessionId": "child999", "sessionId": "sess-child",
            "runtimeKind": "subagent", "parentActiveSessionId": "root222",
        }),
    ];
    let summaries = summaries_from_roster(sessions, &identity, &[]);
    assert_eq!(summaries.len(), 2, "{summaries:?}");
    assert!(summaries.iter().any(|s| s.is_current));
    let sibling = summaries
        .iter()
        .find(|s| s.active_session_id.as_deref() == Some("root222"))
        .unwrap();
    assert_eq!(sibling.relationship, Some(AgentFamilyRelationship::Sibling));
    assert!(!summaries
        .iter()
        .any(|s| s.active_session_id.as_deref() == Some("child999")));
}

#[tokio::test]
async fn family_resolves_a_moved_parent_by_the_peers_roster_alias() {
    let dir = tempfile::TempDir::new().unwrap();
    let socket = dir.path().join("sup.sock");
    spawn_fake_supervisor(
        socket.clone(),
        json!({ "sessions": [
            { "activeSessionId": "aaa111", "sessionId": "sess-a" },
            { "activeSessionId": "rrr777", "sessionId": "sess-p", "sessionName": "papa",
              "sessionPath": "/agent/session-artifacts/sess-g/sub-9/01a0d0a5-e954-71b7-8479-8dc7980768a1.jsonl" },
        ]}),
        None,
    )
    .await;
    let own_summary = Some(json!({
        "activeSessionId": "aaa111",
        "sessionId": "sess-a",
        "parentActiveSessionId": "stale-parent",
        "parentSessionPath": "/old-agent-root/sessions/01a0d0a5-e954-71b7-8479-8dc7980768a1.jsonl",
        "rlmDepth": 1,
    }));
    let controller = controller(socket, own_summary);
    let family = controller.family().await.unwrap();
    assert_eq!(family.len(), 1, "{family:?}");
    assert_eq!(family[0].relationship, AgentFamilyRelationship::Parent);
    assert_eq!(family[0].id, "rrr777");
}

#[tokio::test]
async fn family_joins_a_replaced_child_by_its_durable_ids() {
    let dir = tempfile::TempDir::new().unwrap();
    let socket = dir.path().join("sup.sock");
    spawn_fake_supervisor(
        socket.clone(),
        json!({ "sessions": [
            { "activeSessionId": "aaa111", "sessionId": "sess-a" },
            { "activeSessionId": "new999", "sessionId": "sess-kid",
              "sessionName": "kid", "rlmChildId": "sub-kid1",
              "parentActiveSessionId": "aaa111", "parentSessionId": "sess-a" },
        ]}),
        None,
    )
    .await;
    let controller = controller_with_children(socket, own_summary());
    admit_child(
        &controller,
        RlmChildIdentity {
            rlm_child_id: "sub-kid1".to_string(),
            active_session_id: "ddd444".to_string(),
            session_id: Some("sess-kid".to_string()),
            session_name: "kid".to_string(),
        },
    )
    .await;
    let family = controller.family().await.unwrap();
    let children: Vec<_> = family
        .iter()
        .filter(|member| member.relationship == AgentFamilyRelationship::Child)
        .collect();
    assert_eq!(children.len(), 1, "{family:?}");
    assert_eq!(children[0].id, "new999");
    assert!(children[0].aliases.contains(&"sub-kid1".to_string()));
}

#[tokio::test]
async fn family_resolves_a_moved_parent_by_the_session_file_alias() {
    let dir = tempfile::TempDir::new().unwrap();
    let socket = dir.path().join("sup.sock");
    spawn_fake_supervisor(
        socket.clone(),
        json!({ "sessions": [
            { "activeSessionId": "aaa111", "sessionId": "sess-a" },
            { "activeSessionId": "rrr777", "sessionId": "sess-p", "sessionName": "papa",
              "sessionFile": "/agent/session-artifacts/sess-g/sub-9/01a0d0a5-e954-71b7-8479-8dc7980768a1.jsonl" },
        ]}),
        None,
    )
    .await;
    let own_summary = Some(json!({
        "activeSessionId": "aaa111",
        "sessionId": "sess-a",
        "parentActiveSessionId": "stale-parent",
        "parentSessionPath": "/old-agent-root/sessions/01a0d0a5-e954-71b7-8479-8dc7980768a1.jsonl",
        "rlmDepth": 1,
    }));
    let controller = controller(socket, own_summary);
    let family = controller.family().await.unwrap();
    assert_eq!(family.len(), 1, "{family:?}");
    assert_eq!(family[0].relationship, AgentFamilyRelationship::Parent);
    assert_eq!(family[0].id, "rrr777");
}
