//! Protocol-scoped launch owner authentication; not same-UID isolation.
use anyhow::{anyhow, Result};
use hmac::{Hmac, Mac};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::path::Path;
/// Private in-memory generation state, never serialized.
pub struct LaunchOwner {
    launch_id: String,
    nonce: String,
    key: Vec<u8>,
    instance_id: String,
    _source: Source,
    sequence: u64,
    last: Option<(String, Value)>,
    bootstrap_last: Option<(String, Value)>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Source {
    socket_path: String,
    token: String,
    instance_id: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Setup {
    version: u32,
    kind: String,
    launch_id: String,
    generation_nonce: String,
    daemon_socket_path: String,
    setup_purpose: String,
    owner_key_hex: String,
    source: Source,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Probe {
    version: u32,
    launch_id: String,
    generation_nonce: String,
    sequence: u64,
    payload: String,
    mac_hex: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Payload {
    operation: String,
}
// Recursive duplicate rejection; serde_json Value alone silently replaces keys.
struct StrictValue(Value);
impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = StrictValue;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "strict JSON")
            }
            fn visit_map<M: serde::de::MapAccess<'de>>(
                self,
                mut map: M,
            ) -> std::result::Result<Self::Value, M::Error> {
                let mut out = serde_json::Map::new();
                while let Some(k) = map.next_key::<String>()? {
                    if out.contains_key(&k) {
                        return Err(serde::de::Error::custom("Duplicate private field"));
                    }
                    let v = map.next_value::<StrictValue>()?;
                    out.insert(k, v.0);
                }
                Ok(StrictValue(Value::Object(out)))
            }
            fn visit_seq<S: serde::de::SeqAccess<'de>>(
                self,
                mut seq: S,
            ) -> std::result::Result<Self::Value, S::Error> {
                let mut out = Vec::new();
                while let Some(v) = seq.next_element::<StrictValue>()? {
                    out.push(v.0);
                }
                Ok(StrictValue(Value::Array(out)))
            }
            fn visit_str<E: serde::de::Error>(
                self,
                v: &str,
            ) -> std::result::Result<Self::Value, E> {
                Ok(StrictValue(Value::String(v.into())))
            }
            fn visit_bool<E: serde::de::Error>(
                self,
                v: bool,
            ) -> std::result::Result<Self::Value, E> {
                Ok(StrictValue(v.into()))
            }
            fn visit_u64<E: serde::de::Error>(self, v: u64) -> std::result::Result<Self::Value, E> {
                Ok(StrictValue(v.into()))
            }
            fn visit_i64<E: serde::de::Error>(self, v: i64) -> std::result::Result<Self::Value, E> {
                Ok(StrictValue(v.into()))
            }
            fn visit_f64<E: serde::de::Error>(self, v: f64) -> std::result::Result<Self::Value, E> {
                Ok(StrictValue(serde_json::json!(v)))
            }
            fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<Self::Value, E> {
                Ok(StrictValue(Value::Null))
            }
        }
        d.deserialize_any(Visitor)
    }
}
pub(crate) fn strict(bytes: &[u8]) -> Result<Value> {
    Ok(serde_json::from_slice::<StrictValue>(bytes)?.0)
}
fn unhex(text: &str) -> Result<Vec<u8>> {
    anyhow::ensure!(
        text.len() == 64 && text.bytes().all(|b| b.is_ascii_hexdigit()),
        "Invalid private encoding"
    );
    (0..64)
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).map_err(Into::into))
        .collect()
}
fn id(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 100
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}
fn message(launch: &str, nonce: &str, sequence: u64, payload: &str) -> Vec<u8> {
    let mut bytes = b"prime-studio-owner-probe-v1\0".to_vec();
    for part in [launch, nonce, &sequence.to_string(), payload] {
        bytes.extend_from_slice(&(part.len() as u64).to_be_bytes());
        bytes.extend_from_slice(part.as_bytes());
    }
    bytes
}
impl LaunchOwner {
    pub(crate) fn authenticate_bootstrap(&mut self, value: &Value) -> Result<Value> {
        let probe: Probe = serde_json::from_value(value.clone())?;
        anyhow::ensure!(
            probe.version == 1
                && probe.launch_id == self.launch_id
                && probe.generation_nonce == self.nonce
                && (probe.sequence == self.sequence + 1 || probe.sequence == self.sequence)
                && probe.payload.len() <= 32768,
            "Private bootstrap identity mismatch"
        );
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.key)
            .map_err(|_| anyhow!("Invalid private key"))?;
        mac.update(&message(
            &probe.launch_id,
            &probe.generation_nonce,
            probe.sequence,
            &probe.payload,
        ));
        mac.verify_slice(&unhex(&probe.mac_hex)?)
            .map_err(|_| anyhow!("Private bootstrap authentication failed"))?;
        if probe.sequence == self.sequence {
            return self
                .bootstrap_last
                .as_ref()
                .filter(|(raw, _)| raw == &probe.payload)
                .map(|(_, payload)| payload.clone())
                .ok_or_else(|| anyhow!("Changed bootstrap replay"));
        }
        let mut payload = strict(probe.payload.as_bytes())?;
        anyhow::ensure!(
            matches!(
                payload["operation"].as_str(),
                Some("owner_bootstrap_preflight" | "owner_bootstrap_commit")
            ) && payload.get("pinnedSource").is_none(),
            "Private bootstrap operation unavailable"
        );
        let operation = payload["operation"].as_str().unwrap_or_default();
        let common = [
            "version",
            "operation",
            "rootSessionId",
            "activeSessionId",
            "sessionFile",
            "cwd",
            "expectedGoalId",
            "intendedWork",
        ];
        let commit = [
            "preflightId",
            "operationId",
            "mode",
            "expectedGateRevision",
            "expectedAccountingEpoch",
            "expectedTask",
            "expectedPolicy",
            "expectedAssignments",
            "envelope",
            "callback",
        ];
        anyhow::ensure!(
            payload["version"] == 1
                && payload
                    .as_object()
                    .is_some_and(|obj| obj.keys().all(|k| common.contains(&k.as_str())
                        || (operation == "owner_bootstrap_commit"
                            && commit.contains(&k.as_str())))),
            "Unexpected owner fields"
        );
        anyhow::ensure!(
            [
                "rootSessionId",
                "activeSessionId",
                "sessionFile",
                "cwd",
                "expectedGoalId"
            ]
            .iter()
            .all(|key| payload[*key]
                .as_str()
                .is_some_and(|s| !s.is_empty() && s.len() <= 4096))
                && payload["intendedWork"]
                    .as_object()
                    .is_some_and(|o| o.len() == 2
                        && ["planId", "stepId"].iter().all(|key| o
                            .get(*key)
                            .and_then(Value::as_str)
                            .is_some_and(|s| !s.is_empty()))),
            "Invalid owner target"
        );
        self.sequence = probe.sequence;
        payload["pinnedSource"] = serde_json::json!({"socketPath":self._source.socket_path,"token":self._source.token,"instanceId":self._source.instance_id});
        self.bootstrap_last = Some((probe.payload, payload.clone()));
        Ok(payload)
    }
    pub(crate) fn probe(&mut self, value: &Value) -> Result<Value> {
        let probe: Probe = serde_json::from_value(value.clone())?;
        anyhow::ensure!(
            probe.version == 1
                && probe.launch_id == self.launch_id
                && probe.generation_nonce == self.nonce
                && probe.sequence > 0
                && probe.sequence <= 9007199254740991
                && probe.payload.len() <= 1024,
            "Private owner identity mismatch"
        );
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.key)
            .map_err(|_| anyhow!("Invalid private key"))?;
        mac.update(&message(
            &probe.launch_id,
            &probe.generation_nonce,
            probe.sequence,
            &probe.payload,
        ));
        mac.verify_slice(&unhex(&probe.mac_hex)?)
            .map_err(|_| anyhow!("Private owner authentication failed"))?;
        let payload: Payload = serde_json::from_value(strict(probe.payload.as_bytes())?)?;
        anyhow::ensure!(
            payload.operation == "owner_probe",
            "Private operation unavailable"
        );
        let digest = format!("{:x}", Sha256::digest(probe.payload.as_bytes()));
        if probe.sequence == self.sequence {
            let (old, result) = self
                .last
                .as_ref()
                .ok_or_else(|| anyhow!("Private replay unavailable"))?;
            anyhow::ensure!(old == &digest, "Changed private replay");
            return Ok(result.clone());
        }
        anyhow::ensure!(
            probe.sequence == self.sequence + 1,
            "Stale private sequence"
        );
        self.sequence = probe.sequence;
        let result = serde_json::json!({"version":1,"privateOwnerAuthenticated":true,"launchId":self.launch_id,"generationNonce":self.nonce,"sourceInstanceId":self.instance_id,"operation":"owner_probe","admissionPermission":false,"bootstrapApplied":false});
        self.last = Some((digest, result.clone()));
        Ok(result)
    }
}
/// Consume and close inherited setup before the public supervisor starts.
#[cfg(target_os = "linux")]
pub fn setup(mut stream: std::os::unix::net::UnixStream, socket: &Path) -> Result<LaunchOwner> {
    stream.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(std::time::Duration::from_secs(5)))?;
    let nonce = uuid::Uuid::new_v4().to_string();
    writeln!(
        stream,
        "{}",
        serde_json::json!({"version":1,"kind":"ready","generationNonce":nonce,"supervisorPid":std::process::id()})
    )?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let mut bytes = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        stream.set_read_timeout(Some(
            deadline
                .saturating_duration_since(std::time::Instant::now())
                .max(std::time::Duration::from_millis(1)),
        ))?;
        anyhow::ensure!(
            std::time::Instant::now() < deadline,
            "Private setup deadline"
        );
        anyhow::ensure!(bytes.len() < 16384, "Private setup exceeds bound");
        stream.read_exact(&mut byte)?;
        if byte[0] == b'\n' {
            break;
        }
        bytes.push(byte[0]);
    }
    let setup: Setup = serde_json::from_value(strict(&bytes)?)?;
    anyhow::ensure!(
        setup.version == 1
            && setup.kind == "setup"
            && setup.generation_nonce == nonce
            && id(&setup.launch_id)
            && setup.daemon_socket_path == socket.to_string_lossy()
            && setup.setup_purpose == "source_bootstrap_only"
            && Path::new(&setup.source.socket_path).is_absolute()
            && !setup.source.token.is_empty()
            && id(&setup.source.instance_id),
        "Private setup identity mismatch"
    );
    let key = unhex(&setup.owner_key_hex)?;
    let mut tail = [0u8; 1];
    anyhow::ensure!(
        stream.read(&mut tail)? == 0,
        "Unexpected private setup tail"
    );
    writeln!(
        stream,
        "{}",
        serde_json::json!({"version":1,"kind":"ready_ack","launchId":setup.launch_id,"generationNonce":nonce})
    )?;
    let owner = LaunchOwner {
        launch_id: setup.launch_id,
        nonce,
        key,
        instance_id: setup.source.instance_id.clone(),
        _source: setup.source,
        sequence: 0,
        last: None,
        bootstrap_last: None,
    };
    drop(stream);
    Ok(owner)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn private_launch_rejects_duplicate_json() {
        assert!(strict(br#"{"x":1,"x":2}"#).is_err());
        assert!(strict(br#"{"source":{"x":1,"x":2}}"#).is_err());
    }
    #[test]
    fn private_launch_mac_replay_is_bounded_and_nonmutating() {
        let key = vec![7; 32];
        let mut owner = LaunchOwner {
            launch_id: "launch".into(),
            nonce: "nonce".into(),
            key: key.clone(),
            instance_id: "source".into(),
            _source: Source {
                socket_path: "/bridge".into(),
                token: "private".into(),
                instance_id: "source".into(),
            },
            sequence: 0,
            last: None,
            bootstrap_last: None,
        };
        let payload = r#"{"operation":"owner_probe"}"#;
        let mut mac = Hmac::<Sha256>::new_from_slice(&key).unwrap();
        mac.update(&message("launch", "nonce", 1, payload));
        let hex = mac
            .finalize()
            .into_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let probe = serde_json::json!({"version":1,"launchId":"launch","generationNonce":"nonce","sequence":1,"payload":payload,"macHex":hex});
        let mut bad = probe.clone();
        bad["macHex"] = Value::String("00".repeat(32));
        assert!(owner.probe(&bad).is_err());
        assert_eq!(owner.sequence, 0);
        let first = owner.probe(&probe).unwrap();
        assert_eq!(first["admissionPermission"], false);
        assert_eq!(owner.probe(&probe).unwrap(), first);
        assert_eq!(owner.sequence, 1);
        bad = probe.clone();
        bad["generationNonce"] = Value::String("other".into());
        assert!(owner.probe(&bad).is_err());
    }
}
