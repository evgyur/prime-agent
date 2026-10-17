//! Owner-authenticated Roadmap projection at existing continuation/admission boundaries.
use super::*;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Source {
    socket_path: PathBuf,
    token: String,
    pub(super) instance_id: String,
}
impl std::fmt::Debug for Source {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NextWorkSource([redacted])")
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Binding {
    child_id: String,
    plan_id: String,
    step_id: String,
    snapshot_revision: u64,
    ownership: Vec<String>,
}
impl SupervisorChildSessions {
    pub(crate) async fn invalidate_next_work(&self) -> Result<Value> {
        let _admissions = self.inner.spawn_gate.lock().await;
        let mut gate = self.inner.gate.lock().expect("gate lock");
        gate.next_work = None;
        gate.correction_pending = false;
        gate.revision += 1;
        self.persist_gate(&gate)?;
        Ok(json!({"revision":gate.revision,"nextWorkInvalidated":true}))
    }
    pub(crate) fn install_next_work_source(&self, value: &Value) -> Result<()> {
        let source: Source = serde_json::from_value(value.clone())?;
        anyhow::ensure!(
            !source.token.is_empty()
                && !source.instance_id.is_empty()
                && source.socket_path.is_absolute(),
            "Invalid next_work source"
        );
        let mut gate = self.inner.gate.lock().expect("gate lock");
        gate.next_work_source = Some(source);
        gate.next_work_enabled = true;
        gate.next_work = None;
        self.persist_gate(&gate)
    }
    pub(super) async fn refresh_next_work(&self) {
        let (source, revision) = {
            let gate = self.inner.gate.lock().expect("gate lock");
            if !gate.next_work_enabled {
                return;
            }
            (gate.next_work_source.clone(), gate.revision)
        };
        let identity = self.inner.identity.lock().expect("identity lock").clone();
        let result = async {
            let source = source
                .as_ref()
                .ok_or_else(|| anyhow!("next_work owner must rebind after recovery"))?;
            let mut offset = 0;
            let mut combined: Option<Value> = None;
            loop {
                let body = serde_json::to_vec(&json!({"action":"next_work", "identity":{
                "sessionId":identity.session_id,"sessionFile":identity.session_file,"cwd":identity.cwd},
                "params":{"instanceId":source.instance_id,"offset":offset,"limit":50,"expectedRevision":combined.as_ref().and_then(|value| value["revision"].as_u64())}}))?;
                let stream =
                    pa_types::platform::transport::connect_transport(&source.socket_path).await?;
                let (reader, mut writer) = stream.split();
                let header = format!("POST / HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", source.token, body.len());
                writer.write_all(header.as_bytes()).await?;
                writer.write_all(&body).await?;
                let mut bytes = Vec::new();
                reader.take(131_073).read_to_end(&mut bytes).await?;
                anyhow::ensure!(bytes.len() <= 131_072, "next_work response exceeds bound");
                let boundary = bytes
                    .windows(4)
                    .position(|part| part == b"\r\n\r\n")
                    .ok_or_else(|| anyhow!("Invalid next_work HTTP response"))?;
                anyhow::ensure!(
                    bytes.starts_with(b"HTTP/1.1 200 ") || bytes.starts_with(b"HTTP/1.0 200 "),
                    "next_work owner unavailable"
                );
                let value: Value = serde_json::from_slice(&bytes[boundary + 4..])?;
                anyhow::ensure!(
                    value["schemaVersion"] == 1
                        && value["instanceId"].as_str() == Some(source.instance_id.as_str())
                        && value["revision"].as_u64().is_some()
                        && value["items"].is_array(),
                    "Unsupported next_work projection"
                );
                if let Some(first) = &mut combined {
                    anyhow::ensure!(
                        value["revision"] == first["revision"],
                        "next_work changed during pagination"
                    );
                    first["items"]
                        .as_array_mut()
                        .unwrap()
                        .extend(value["items"].as_array().unwrap().iter().cloned());
                } else {
                    combined = Some(value.clone());
                }
                match value["nextOffset"].as_u64() {
                    Some(next) => {
                        anyhow::ensure!(next > offset, "Invalid next_work page");
                        offset = next;
                    }
                    None => break,
                }
            }
            let mut value = combined.unwrap();
            anyhow::ensure!(
                value["total"].as_u64()
                    == value["items"].as_array().map(|items| items.len() as u64),
                "Incomplete next_work pages"
            );
            value["complete"] = json!(true);
            Ok::<_, anyhow::Error>(value)
        };
        let snapshot = match tokio::time::timeout(Duration::from_millis(2_000), result).await {
            Ok(Ok(value)) => Some(value),
            Ok(Err(_)) | Err(_) => None,
        };
        let deleted = self
            .inner
            .deleted_children
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        let mut gate = self.inner.gate.lock().expect("gate lock");
        if gate.revision != revision {
            return;
        }
        if let Some(snapshot) = &snapshot {
            let accepted = snapshot["items"].as_array().cloned().unwrap_or_default();
            gate.work_bindings.retain(|binding| {
                !(deleted.contains(&binding.child_id)
                    && accepted.iter().any(|item| {
                        item["planId"] == binding.plan_id
                            && item["stepId"] == binding.step_id
                            && item["status"] == "accepted"
                    }))
            });
        }
        if gate.next_work != snapshot {
            let accepted_progress = snapshot
                .as_ref()
                .and_then(|value| value["items"].as_array())
                .is_some_and(|items| {
                    items.iter().any(|item| {
                        item["status"] == "accepted"
                            && gate
                                .next_work
                                .as_ref()
                                .and_then(|old| old["items"].as_array())
                                .is_some_and(|old_items| {
                                    old_items.iter().any(|old| {
                                        old["planId"] == item["planId"]
                                            && old["stepId"] == item["stepId"]
                                            && old["status"] != "accepted"
                                    })
                                })
                    })
                });
            if accepted_progress {
                gate.attempts = 0;
            }
            if gate.next_work.is_some() {
                gate.revision += 1;
            }
            gate.next_work = snapshot;
            gate.correction_pending = false;
        }
    }
    pub(super) fn next_work_view(&self, gate: &Gate, rows: &[Value]) -> Value {
        if !gate.next_work_enabled {
            return Value::Null;
        }
        let reserved = rows
            .iter()
            .filter(|row| row["obligation"] == true || row["executionKind"] == "unknown")
            .count();
        let free = gate
            .policy
            .as_ref()
            .map_or(0, |p| p.max_active.saturating_sub(reserved));
        let mut snapshot = gate
            .next_work
            .clone()
            .unwrap_or_else(|| json!({"complete":false,"items":[]}));
        let items = snapshot["items"].as_array().cloned().unwrap_or_default();
        let ready: Vec<Value> = items
            .iter()
            .filter(|item| {
                item["status"] == "ready"
                    && !gate.work_bindings.iter().any(|binding| {
                        item["planId"] == binding.plan_id && item["stepId"] == binding.step_id
                            || item["ownership"].as_array().is_some_and(|owners| {
                                binding
                                    .ownership
                                    .iter()
                                    .any(|owner| owners.iter().any(|v| v == owner))
                            })
                    })
            })
            .cloned()
            .collect();
        let acceptance: Vec<Value> = gate.work_bindings.iter().filter(|binding| rows.iter().any(|row| row["childId"] == binding.child_id && row["obligation"] == false) && !items.iter().any(|item| item["planId"] == binding.plan_id && item["stepId"] == binding.step_id && item["status"] == "accepted")).map(|binding| json!({"childId":binding.child_id,"planId":binding.plan_id,"stepId":binding.step_id})).collect();
        snapshot["actionRequired"] = json!(!acceptance.is_empty() || free > 0 && !ready.is_empty());
        snapshot["runtime"] = json!({"complete":rows.iter().all(|row| row["executionKind"] != "unknown"),"freeSlots":free,"ownership":gate.work_bindings,"ready":ready,"awaitingAcceptance":acceptance});
        snapshot
    }
    pub(crate) async fn reserve_work(&self, child_id: &str, work: Option<&Value>) -> Result<()> {
        let mut gate = self.inner.gate.lock().expect("gate lock");
        if !gate.next_work_enabled {
            anyhow::ensure!(work.is_none(), "next_work is not activated by Studio");
            return Ok(());
        }
        anyhow::ensure!(
            gate.enabled() && !gate.suspended,
            "next_work admissions suspended"
        );
        let work =
            work.ok_or_else(|| anyhow!("Owner-scoped work ref is required before admission"))?;
        let snapshot = gate
            .next_work
            .as_ref()
            .ok_or_else(|| anyhow!("next_work source unknown; reconcile without resending"))?;
        anyhow::ensure!(
            snapshot["complete"] == true
                && work["snapshotRevision"].as_u64() == snapshot["revision"].as_u64(),
            "Incomplete or stale next_work admission"
        );
        let item = snapshot["items"]
            .as_array()
            .and_then(|items| {
                items.iter().find(|item| {
                    item["planId"] == work["planId"]
                        && item["stepId"] == work["stepId"]
                        && item["status"] == "ready"
                })
            })
            .ok_or_else(|| anyhow!("Work is not ready in owner-scoped Roadmap"))?;
        let ownership: Vec<String> = serde_json::from_value(item["ownership"].clone())?;
        anyhow::ensure!(
            !gate
                .work_bindings
                .iter()
                .any(|binding| binding.child_id == child_id
                    || item["planId"] == binding.plan_id && item["stepId"] == binding.step_id
                    || ownership
                        .iter()
                        .any(|owner| binding.ownership.contains(owner))),
            "Work or ownership remains reserved until confirmed STOP and acceptance/handoff"
        );
        let binding = Binding {
            child_id: child_id.into(),
            plan_id: item["planId"]
                .as_str()
                .ok_or_else(|| anyhow!("Invalid work plan"))?
                .into(),
            step_id: item["stepId"]
                .as_str()
                .ok_or_else(|| anyhow!("Invalid work step"))?
                .into(),
            snapshot_revision: snapshot["revision"].as_u64().unwrap(),
            ownership,
        };
        gate.work_bindings.push(binding);
        gate.attempts = 0;
        gate.revision += 1;
        self.persist_gate(&gate)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn sessions() -> SupervisorChildSessions {
        let sessions = SupervisorChildSessions::new(
            Arc::new(crate::supervisor_link::SupervisorLink::new(PathBuf::new())),
            std::env::temp_dir(),
            "parent".into(),
            Arc::new(crate::model_allowlist::ModelRefusalTelemetry::new(
                std::env::temp_dir(),
                true,
            )),
        );
        sessions.set_identity(ParentIdentity {
            session_id: Some("root".into()),
            session_file: None,
            cwd: Some("/tmp".into()),
            ..ParentIdentity::with_default_depth()
        });
        sessions
    }
    async fn source(sessions: &SupervisorChildSessions, value: Value) -> tempfile::TempDir {
        let dir = tempfile::TempDir::new().unwrap();
        let socket = dir.path().join("roadmap.sock");
        sessions.inner.identity.lock().unwrap().session_file =
            Some(dir.path().join("root.jsonl").display().to_string());
        let listener = pa_types::platform::transport::bind_transport(&socket)
            .await
            .unwrap();
        tokio::spawn(async move {
            loop {
                let stream = listener.accept().await.unwrap();
                let value = value.clone();
                tokio::spawn(async move {
                    let (mut reader, mut writer) = stream.split();
                    let mut request = Vec::new();
                    loop {
                        let mut byte = [0u8; 1];
                        reader.read_exact(&mut byte).await.unwrap();
                        request.push(byte[0]);
                        if request.ends_with(b"\r\n\r\n") {
                            break;
                        }
                    }
                    let header = String::from_utf8(request).unwrap();
                    assert!(header.contains("Authorization: Bearer fixture"));
                    let length: usize = header
                        .lines()
                        .find_map(|line| line.strip_prefix("Content-Length: "))
                        .unwrap()
                        .parse()
                        .unwrap();
                    let mut body = vec![0u8; length];
                    reader.read_exact(&mut body).await.unwrap();
                    let input: Value = serde_json::from_slice(&body).unwrap();
                    assert_eq!(input["action"], "next_work");
                    assert_eq!(input["identity"]["sessionId"], "root");
                    assert_eq!(input["params"]["instanceId"], "instance");
                    assert!(input["params"].get("planIds").is_none());
                    let body = serde_json::to_vec(&value).unwrap();
                    writer.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len()).as_bytes()).await.unwrap();
                    writer.write_all(&body).await.unwrap();
                });
            }
        });
        sessions
            .install_next_work_source(
                &json!({"socketPath":socket,"token":"fixture","instanceId":"instance"}),
            )
            .unwrap();
        let mut gate = sessions.inner.gate.lock().unwrap();
        gate.policy = Some(serde_json::from_value(json!({"version":1,"enabled":true,"minActive":1,"maxActive":2,"rootWritesCode":false,"correctiveBudget":2})).unwrap());
        drop(gate);
        sessions.refresh_next_work().await;
        dir
    }
    fn projection() -> Value {
        json!({"schemaVersion":1,"instanceId":"instance","revision":7,"complete":true,"total":3,"nextOffset":null,
            "items":[{"planId":"p","stepId":"A","status":"blocked","ownership":["a"]},
            {"planId":"p","stepId":"B","status":"ready","ownership":["b"]},
            {"planId":"p","stepId":"D","status":"ready","ownership":["d"]}]})
    }
    #[tokio::test]
    async fn trusted_source_binds_before_admission_and_rejects_stale_blocked_duplicate_ownership() {
        let sessions = sessions();
        let _source = source(&sessions, projection()).await;
        for work in [
            json!({"planId":"p","stepId":"A","snapshotRevision":7}),
            json!({"planId":"p","stepId":"B","snapshotRevision":6}),
        ] {
            assert!(sessions.reserve_work("kid", Some(&work)).await.is_err());
        }
        let work = json!({"planId":"p","stepId":"B","snapshotRevision":7});
        sessions.reserve_work("B", Some(&work)).await.unwrap();
        assert!(sessions
            .reserve_work("duplicate", Some(&work))
            .await
            .is_err());
        let gate = sessions.inner.gate.lock().unwrap().clone();
        assert_eq!(gate.work_bindings.len(), 1);
        let view = sessions.next_work_view(
            &gate,
            &[
                json!({"childId":"B","obligation":false,"executionKind":"idle"}),
                json!({"childId":"C","obligation":true,"executionKind":"executing"}),
            ],
        );
        assert_eq!(view["runtime"]["freeSlots"], 1);
        assert_eq!(view["runtime"]["ready"][0]["stepId"], "D");
        assert_eq!(view["actionRequired"], true);
        assert_eq!(view["runtime"]["awaitingAcceptance"][0]["stepId"], "B");
        sessions
            .reserve_work(
                "D",
                Some(&json!({"planId":"p","stepId":"D","snapshotRevision":7})),
            )
            .await
            .unwrap();
        assert_eq!(sessions.inner.gate.lock().unwrap().work_bindings.len(), 2);
    }
    #[tokio::test]
    async fn missing_or_wrong_instance_source_fails_closed_and_credentials_are_not_serialized() {
        let sessions = sessions();
        let mut value = projection();
        value["instanceId"] = json!("stale");
        let _source = source(&sessions, value).await;
        assert!(sessions
            .reserve_work(
                "B",
                Some(&json!({"planId":"p","stepId":"B","snapshotRevision":7}))
            )
            .await
            .is_err());
        let gate = sessions.inner.gate.lock().unwrap();
        let stored = serde_json::to_string(&*gate).unwrap();
        assert!(!stored.contains("fixture"));
        assert!(!stored.contains("token"));
        assert!(gate.next_work.is_none());
    }
    #[tokio::test]
    async fn invalidation_waits_for_admission_lock_and_revokes_snapshot_and_control() {
        let sessions = sessions();
        let _source = source(&sessions, projection()).await;
        sessions.refresh_next_work().await;
        let prior = sessions.inner.gate.lock().unwrap().revision;
        {
            let mut gate = sessions.inner.gate.lock().unwrap();
            gate.correction_pending = true;
        }
        let admission = sessions.inner.spawn_gate.lock().await;
        let invalidating = sessions.clone();
        let mut invalidation = Box::pin(invalidating.invalidate_next_work());
        assert!(futures::poll!(invalidation.as_mut()).is_pending());
        assert!(sessions.inner.gate.lock().unwrap().next_work.is_some());
        drop(admission);
        let result = invalidation.await.unwrap();
        assert_eq!(
            result,
            json!({"revision":prior+1,"nextWorkInvalidated":true})
        );
        let gate = sessions.inner.gate.lock().unwrap();
        assert!(gate.next_work.is_none());
        assert!(!gate.correction_pending);
        assert!(gate.next_work_source.is_some());
        drop(gate);
        assert!(sessions
            .reserve_work(
                "stale",
                Some(&json!({"planId":"p","stepId":"B","snapshotRevision":7}))
            )
            .await
            .is_err());
    }
    #[tokio::test]
    async fn model_cannot_install_or_invalidate_owner_source() {
        let sessions = sessions();
        for field in ["nextWorkSource", "nextWork", "invalidateNextWork"] {
            let mut payload = json!({"expectedRevision":0,"policy":{},"task":{},"assignments":[]});
            payload[field] = json!(true);
            let error = sessions.configure_gate(&payload).await.unwrap_err();
            assert!(error.to_string().contains("Studio owner"));
        }
    }
}
