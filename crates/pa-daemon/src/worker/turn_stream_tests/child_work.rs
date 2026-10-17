//! A queued child consults its owner before the provider is called.
use super::*;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
struct ProviderProbe(std::sync::atomic::AtomicUsize);
impl SessionEngine for ProviderProbe {
    fn run_prompt(
        &self,
        _index: usize,
        _request: PromptRequest,
        _aborted: &dyn Fn() -> bool,
        emit: &mut dyn FnMut(EngineEvent) -> bool,
    ) {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        emit(EngineEvent::Done(Ok(())));
    }
    fn run_side_question(
        &self,
        _request: SideQuestionRequest,
        _signal: &pa_agent::abort::AbortSignal,
        _sink: &pa_core::session_engine::side_question::SideQuestionSink,
    ) -> SideQuestionOutcome {
        SideQuestionOutcome::Failed {
            answer: String::new(),
            error: "unsupported".into(),
        }
    }
    fn run_compaction(
        &self,
        _request: CompactionRequest,
        _signal: &pa_agent::abort::AbortSignal,
    ) -> CompactionOutcome {
        CompactionOutcome::Skipped {
            message: "unsupported".into(),
        }
    }
    fn run_branch_summary(
        &self,
        _request: crate::engine::BranchSummaryRequest,
        _signal: &pa_agent::abort::AbortSignal,
    ) -> crate::engine::BranchSummaryOutcome {
        crate::engine::BranchSummaryOutcome::Failed {
            error: "unsupported".into(),
        }
    }
    fn rebuild_session_context(
        &self,
        _entries: Vec<pa_types::session::FileEntry>,
        _reload: pa_core::session_engine::goal_driver::GoalBranchReload,
    ) -> anyhow::Result<()> {
        Ok(())
    }
}
#[tokio::test]
async fn changed_owner_snapshot_before_queued_child_provider_holds_item_without_model_call() {
    let dir = tempfile::TempDir::new().unwrap();
    let socket = dir.path().join("owner.sock");
    let listener = pa_types::platform::transport::bind_transport(&socket)
        .await
        .unwrap();
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let stream = listener.accept().await.unwrap();
        let (reader, mut writer) = stream.split();
        writer.write_all(b"{\"type\":\"daemon_hello\",\"protocol\":{\"name\":\"prime-agent.daemon\",\"version\":7}}\n").await.unwrap();
        let mut reader = BufReader::new(reader);
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        let request: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(request["command"]["type"], "configure_orchestration_gate");
        assert_eq!(request["command"]["activeSessionId"], "owner");
        let permit = &request["command"]["beginWorkStart"];
        assert_eq!(permit["childActiveSessionId"], "burst-session");
        assert_eq!(permit["expectedMessageId"], "kickoff");
        assert_eq!(permit["admissionGeneration"], "generation");
        entered_tx.send(()).unwrap();
        release_rx.await.unwrap();
        let response = crate::protocol::response_success(
            request["id"].as_str(),
            "configure_orchestration_gate",
            Some(json!({"workStartPermitted":false})),
        );
        writer
            .write_all(format!("{}\n", serde_json::to_string(&response).unwrap()).as_bytes())
            .await
            .unwrap();
    });
    let engine = Arc::new(ProviderProbe(std::sync::atomic::AtomicUsize::new(0)));
    let mut runner = burst_runner(engine.clone());
    runner.passivation.link = Arc::new(crate::supervisor_link::SupervisorLink::new(socket));
    runner.core.lock().unwrap().follow_up.push_back(QueuedItem {message:"child task".into(),priority:QueuePriority::Background,preview:None,custom_message:Some(json!({"role":"custom","customType":"agent_message","details":{"id":"kickoff"},"nativeWorkPermit":{"ownerActiveSessionId":"owner","sourceInstanceId":"source","childId":"child","childActiveSessionId":"burst-session","childSessionId":"durable","admissionGeneration":"generation","expectedMessageId":"kickoff","planId":"p","stepId":"d","startToken":"private"}})),agent_message:None,queue_key:None,admission_id:None,images:Vec::new(),done:None,queue_visible:false,policy:TurnPolicy::Injected,forced_batch:false});
    let core = runner.core.clone();
    let idle = runner.idle_notify.clone();
    let running = tokio::spawn(runner.run());
    entered_rx.await.unwrap();
    let suspended = idle.notified();
    release_tx.send(()).unwrap();
    suspended.await;
    {
        let core = core.lock().unwrap();
        assert!(core.queued_input_suspended);
        assert_eq!(core.follow_up.len(), 1);
    }
    assert_eq!(engine.0.load(std::sync::atomic::Ordering::SeqCst), 0);
    core.lock().unwrap().shutdown_requested = true;
    running.abort();
    server.await.unwrap();
}
