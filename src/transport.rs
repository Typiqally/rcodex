use std::collections::{HashMap, VecDeque};

use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use futures_util::{SinkExt, StreamExt};
use serde_json::{Map, Value, json};
use tokio::time::{Duration, timeout};
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream, connect_async,
    tungstenite::{
        Message,
        client::IntoClientRequest,
        http::{HeaderValue, header::AUTHORIZATION},
    },
};
use url::Url;
use uuid::Uuid;

use crate::{
    auth::CodexAuth,
    device_key::sign_with_os_protected_device_key,
    protocol::{
        API_BASE, ConnectionChallenge, EnrollmentRecord, RELAY_PROTOCOL_VERSION,
        client_message_envelope,
    },
    relay::{RemoteControlSession, validate_and_build_connection_signing_payload},
};

const SEGMENT_TARGET_BYTES: usize = 100 * 1024;
const MAX_FRAME_BYTES: usize = 150 * 1024;
const MAX_MESSAGE_BYTES: usize = 64 * 1024 * 1024;
const MAX_SEGMENTS: usize = MAX_MESSAGE_BYTES.div_ceil(SEGMENT_TARGET_BYTES);
const MAX_CONCURRENT_ASSEMBLIES: usize = 8;
const MAX_BUFFERED_ASSEMBLY_BYTES: usize = MAX_MESSAGE_BYTES;

type RelaySocket = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

pub struct RelayTransport {
    client_id: String,
    environment_id: String,
    next_client_sequence: u64,
    pending_request_ids: VecDeque<Value>,
    reassembler: ServerMessageReassembler,
    seen_server_sequence: Option<u64>,
    socket: Option<RelaySocket>,
    stream_id: String,
}

impl RelayTransport {
    pub async fn connect(
        auth: &CodexAuth,
        enrollment: &EnrollmentRecord,
        session: &RemoteControlSession,
        environment_id: &str,
    ) -> Result<Self> {
        let url = relay_websocket_url()?;
        let mut request = url
            .as_str()
            .into_client_request()
            .context("build remote-control websocket request")?;
        let headers = request.headers_mut();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", auth.access_token()))
                .context("Codex access token cannot be used as a header")?,
        );
        headers.insert(
            "ChatGPT-Account-Id",
            HeaderValue::from_str(auth.account_id())
                .context("ChatGPT account ID cannot be used as a header")?,
        );
        headers.insert(
            "x-codex-client-id",
            HeaderValue::from_str(&enrollment.client_id)
                .context("rcodex client ID cannot be used as a header")?,
        );
        headers.insert(
            "x-codex-protocol-version",
            HeaderValue::from_str(&RELAY_PROTOCOL_VERSION.to_string())?,
        );
        headers.insert(
            "x-codex-client-session-token",
            HeaderValue::from_str(&format!("Bearer {}", session.remote_control_token))
                .context("relay session token cannot be used as a header")?,
        );

        let (mut socket, _) = timeout(Duration::from_secs(15), connect_async(request))
            .await
            .context("remote-control websocket handshake timed out")?
            .context("open remote-control websocket")?;
        let challenge_message = timeout(Duration::from_secs(10), socket.next())
            .await
            .context("remote-control device-key challenge timed out")?
            .context("remote-control websocket closed before device-key challenge")?
            .context("read remote-control device-key challenge")?;
        let challenge_value = parse_text_message(challenge_message)?;
        if challenge_value.get("type").and_then(Value::as_str) != Some("device_key_challenge") {
            bail!("remote-control websocket did not send a device-key challenge");
        }
        let challenge: ConnectionChallenge = serde_json::from_value(challenge_value)
            .context("parse remote-control device-key challenge")?;
        let signed_payload = validate_and_build_connection_signing_payload(
            enrollment,
            session,
            &challenge,
            chrono::Utc::now().timestamp(),
        )?;
        let signature = sign_with_os_protected_device_key(&enrollment.key_id, &signed_payload)?;
        socket
            .send(Message::Text(
                serde_json::to_string(&json!({
                    "type": "device_key_proof",
                    "keyId": enrollment.key_id,
                    "signatureDerBase64": STANDARD.encode(signature),
                    "signedPayloadBase64": STANDARD.encode(signed_payload),
                    "algorithm": enrollment.algorithm,
                }))?
                .into(),
            ))
            .await
            .context("send websocket device-key proof")?;

        Ok(Self {
            client_id: enrollment.client_id.clone(),
            environment_id: environment_id.into(),
            next_client_sequence: 1,
            pending_request_ids: VecDeque::new(),
            reassembler: ServerMessageReassembler::default(),
            seen_server_sequence: None,
            socket: Some(socket),
            stream_id: Uuid::new_v4().to_string(),
        })
    }

    pub async fn send_app_message(&mut self, message: Value) -> Result<()> {
        for segment in self.outgoing_app_segments(message)? {
            self.socket
                .as_mut()
                .context("remote-control websocket is not available")?
                .send(Message::Text(serde_json::to_string(&segment)?.into()))
                .await
                .context("send remote-control client message")?;
        }
        Ok(())
    }

    fn outgoing_app_segments(&mut self, message: Value) -> Result<Vec<Value>> {
        if message.get("method").and_then(Value::as_str) == Some("initialize") {
            self.stream_id = Uuid::new_v4().to_string();
            self.next_client_sequence = 1;
            self.seen_server_sequence = None;
            self.pending_request_ids.clear();
            self.reassembler = ServerMessageReassembler::default();
        }
        if let Some(id) = message
            .get("id")
            .filter(|id| id.is_string() || id.is_number())
        {
            self.pending_request_ids.push_back(id.clone());
        }
        let envelope = client_message_envelope(
            &self.client_id,
            &self.environment_id,
            &self.stream_id,
            self.next_client_sequence,
            message,
        );
        self.next_client_sequence = self.next_client_sequence.saturating_add(1);
        segment_client_message(&envelope)
    }

    pub async fn receive_app_message(&mut self) -> Result<Value> {
        loop {
            let frame = self
                .socket
                .as_mut()
                .context("remote-control websocket is not available")?
                .next()
                .await
                .context("remote-control websocket closed")?
                .context("read remote-control websocket frame")?;
            match frame {
                Message::Ping(payload) => {
                    self.socket
                        .as_mut()
                        .context("remote-control websocket is not available")?
                        .send(Message::Pong(payload))
                        .await
                        .context("answer remote-control websocket ping")?;
                }
                Message::Close(frame) => {
                    bail!("remote-control websocket closed: {frame:?}");
                }
                Message::Text(_) | Message::Binary(_) => {
                    let envelope = parse_text_message(frame)?;
                    if let Some(message) = self.observe_server_envelope(envelope)? {
                        return Ok(message);
                    }
                }
                Message::Pong(_) | Message::Frame(_) => {}
            }
        }
    }

    fn observe_server_envelope(&mut self, envelope: Value) -> Result<Option<Value>> {
        let kind = envelope.get("type").and_then(Value::as_str);
        if matches!(kind, Some("ack" | "pong")) {
            return Ok(None);
        }
        if !matches!(kind, Some("server_message" | "server_message_chunk")) {
            return Ok(None);
        }
        if !server_envelope_targets_active_stream(
            &envelope,
            &self.client_id,
            &self.environment_id,
            &self.stream_id,
        )? {
            return Ok(None);
        }
        let Some(envelope) = self.reassembler.observe(&envelope)? else {
            return Ok(None);
        };
        let sequence = envelope
            .get("seq_id")
            .and_then(Value::as_u64)
            .context("server message has no sequence ID")?;
        if self
            .seen_server_sequence
            .is_some_and(|seen| sequence <= seen)
        {
            return Ok(None);
        }
        if self
            .seen_server_sequence
            .is_some_and(|seen| sequence != seen.saturating_add(1))
        {
            bail!("remote-control server message sequence gap");
        }
        self.seen_server_sequence = Some(sequence);
        let mut message = envelope
            .get("message")
            .cloned()
            .context("server message has no app-server payload")?;
        if message.get("type").and_then(Value::as_str) == Some("error")
            && message.get("id").is_none()
        {
            let id = self
                .pending_request_ids
                .pop_front()
                .context("remote-control error has no pending request")?;
            let object = message
                .as_object_mut()
                .context("remote-control error payload is not an object")?;
            object.remove("type");
            message = json!({"id": id, "error": object});
        } else if let Some(id) = message.get("id")
            && let Some(position) = self
                .pending_request_ids
                .iter()
                .position(|pending| pending == id)
        {
            self.pending_request_ids.remove(position);
        }
        Ok(Some(message))
    }

    pub async fn bridge_local(
        mut self,
        local: WebSocketStream<tokio::net::TcpStream>,
    ) -> Result<()> {
        let socket = self
            .socket
            .take()
            .context("remote-control websocket is not available")?;
        let (mut relay_writer, mut relay_reader) = socket.split();
        let (mut local_writer, mut local_reader) = local.split();
        loop {
            tokio::select! {
                local_frame = local_reader.next() => {
                    let Some(local_frame) = local_frame else { break };
                    match local_frame.context("read local Codex websocket frame")? {
                        Message::Text(text) => {
                            let message = serde_json::from_str(&text)
                                .context("local Codex websocket message is not JSON")?;
                            for segment in self.outgoing_app_segments(message)? {
                                relay_writer.send(Message::Text(serde_json::to_string(&segment)?.into()))
                                    .await.context("forward local Codex message to relay")?;
                            }
                        }
                        Message::Binary(bytes) => {
                            let message = serde_json::from_slice(&bytes)
                                .context("local Codex websocket message is not JSON")?;
                            for segment in self.outgoing_app_segments(message)? {
                                relay_writer.send(Message::Text(serde_json::to_string(&segment)?.into()))
                                    .await.context("forward local Codex message to relay")?;
                            }
                        }
                        Message::Ping(bytes) => {
                            local_writer.send(Message::Pong(bytes)).await
                                .context("answer local Codex websocket ping")?;
                        }
                        Message::Close(_) => break,
                        Message::Pong(_) | Message::Frame(_) => {}
                    }
                }
                relay_frame = relay_reader.next() => {
                    let Some(relay_frame) = relay_frame else {
                        bail!("remote-control relay websocket closed");
                    };
                    match relay_frame.context("read remote-control websocket frame")? {
                        Message::Text(text) => {
                            let envelope = serde_json::from_str(&text)
                                .context("remote-control websocket frame is not JSON")?;
                            if let Some(message) = self.observe_server_envelope(envelope)? {
                                local_writer.send(Message::Text(serde_json::to_string(&message)?.into()))
                                    .await.context("forward relay message to local Codex")?;
                            }
                        }
                        Message::Binary(bytes) => {
                            let envelope = serde_json::from_slice(&bytes)
                                .context("remote-control websocket frame is not JSON")?;
                            if let Some(message) = self.observe_server_envelope(envelope)? {
                                local_writer.send(Message::Text(serde_json::to_string(&message)?.into()))
                                    .await.context("forward relay message to local Codex")?;
                            }
                        }
                        Message::Ping(bytes) => {
                            relay_writer.send(Message::Pong(bytes)).await
                                .context("answer remote-control websocket ping")?;
                        }
                        Message::Close(frame) => {
                            bail!("remote-control websocket closed: {frame:?}");
                        }
                        Message::Pong(_) | Message::Frame(_) => {}
                    }
                }
            }
        }
        let close = json!({
            "type": "client_closed",
            "client_id": self.client_id,
            "seq_id": self.next_client_sequence,
            "stream_id": self.stream_id,
            "env_id": self.environment_id,
        });
        let _ = relay_writer
            .send(Message::Text(serde_json::to_string(&close)?.into()))
            .await;
        let _ = relay_writer.close().await;
        let _ = local_writer.close().await;
        Ok(())
    }

    pub async fn close(mut self) -> Result<()> {
        let envelope = json!({
            "type": "client_closed",
            "client_id": self.client_id,
            "seq_id": self.next_client_sequence,
            "stream_id": self.stream_id,
            "env_id": self.environment_id,
        });
        let mut socket = self
            .socket
            .take()
            .context("remote-control websocket is not available")?;
        socket
            .send(Message::Text(serde_json::to_string(&envelope)?.into()))
            .await
            .context("send remote-control client close")?;
        socket.close(None).await.context("close relay websocket")
    }
}

pub fn relay_websocket_url() -> Result<Url> {
    let mut url = Url::parse(&format!("{API_BASE}/codex/remote/control/client"))?;
    url.set_scheme(if url.scheme() == "https" { "wss" } else { "ws" })
        .map_err(|_| anyhow::anyhow!("could not set relay websocket scheme"))?;
    Ok(url)
}

pub fn segment_client_message(envelope: &Value) -> Result<Vec<Value>> {
    let serialized = serde_json::to_vec(envelope).context("serialize relay client envelope")?;
    if serialized.len() <= SEGMENT_TARGET_BYTES {
        return Ok(vec![envelope.clone()]);
    }
    if envelope.get("type").and_then(Value::as_str) != Some("client_message") {
        bail!("only client_message envelopes can be segmented");
    }
    let message = envelope
        .get("message")
        .context("client message envelope has no message")?;
    let message_bytes = serde_json::to_vec(message).context("serialize app-server message")?;
    if message_bytes.len() > MAX_MESSAGE_BYTES {
        bail!("app-server message exceeds the relay size limit");
    }
    let mut segment_count = message_bytes.len().div_ceil(SEGMENT_TARGET_BYTES).max(1);
    loop {
        let chunk_size = message_bytes.len().div_ceil(segment_count).max(1);
        let chunks: Vec<_> = message_bytes.chunks(chunk_size).collect();
        segment_count = chunks.len();
        let segments: Vec<_> = chunks
            .into_iter()
            .enumerate()
            .map(|(segment_id, chunk)| {
                let mut segment = envelope.as_object().cloned().unwrap_or_default();
                segment.insert("type".into(), Value::String("client_message_chunk".into()));
                segment.remove("message");
                segment.insert("segment_id".into(), segment_id.into());
                segment.insert("segment_count".into(), segment_count.into());
                segment.insert("message_size_bytes".into(), message_bytes.len().into());
                segment.insert(
                    "message_chunk_base64".into(),
                    Value::String(STANDARD.encode(chunk)),
                );
                Value::Object(segment)
            })
            .collect();
        if segments.iter().all(|segment| {
            serde_json::to_vec(segment).is_ok_and(|bytes| bytes.len() <= MAX_FRAME_BYTES)
        }) {
            return Ok(segments);
        }
        if chunk_size == 1 {
            bail!("relay segment metadata exceeds the frame size limit");
        }
        segment_count = segment_count.saturating_add(1);
    }
}

#[derive(Default)]
pub struct ServerMessageReassembler {
    assemblies: HashMap<String, Assembly>,
    buffered_bytes: usize,
}

struct Assembly {
    chunks: Vec<Option<Vec<u8>>>,
    first: Map<String, Value>,
    message_size: usize,
    received_bytes: usize,
}

impl ServerMessageReassembler {
    pub fn observe(&mut self, envelope: &Value) -> Result<Option<Value>> {
        if envelope.get("type").and_then(Value::as_str) != Some("server_message_chunk") {
            return Ok(Some(envelope.clone()));
        }
        if serde_json::to_vec(envelope)?.len() > MAX_FRAME_BYTES {
            bail!("remote-control server segment exceeds the frame limit");
        }
        let object = envelope
            .as_object()
            .context("remote-control server segment is not an object")?;
        let segment_id = usize_field(object, "segment_id")?;
        let segment_count = usize_field(object, "segment_count")?;
        let message_size = usize_field(object, "message_size_bytes")?;
        if segment_count <= 1
            || segment_count > MAX_SEGMENTS
            || segment_id >= segment_count
            || message_size == 0
            || message_size > MAX_MESSAGE_BYTES
        {
            bail!("remote-control server segment metadata is invalid");
        }
        let key = format!(
            "{}:{}:{}",
            string_field(object, "env_id")?,
            string_field(object, "stream_id")?,
            usize_field(object, "seq_id")?
        );
        let chunk = STANDARD
            .decode(string_field(object, "message_chunk_base64")?)
            .context("remote-control server segment is not base64")?;
        if chunk.is_empty() || chunk.len() > message_size {
            bail!("remote-control server segment has an invalid decoded size");
        }
        if !self.assemblies.contains_key(&key) && self.assemblies.len() >= MAX_CONCURRENT_ASSEMBLIES
        {
            bail!("too many incomplete remote-control server messages");
        }
        let assembly = self
            .assemblies
            .entry(key.clone())
            .or_insert_with(|| Assembly {
                chunks: vec![None; segment_count],
                first: object.clone(),
                message_size,
                received_bytes: 0,
            });
        if assembly.chunks.len() != segment_count || assembly.message_size != message_size {
            self.remove_assembly(&key);
            bail!("remote-control server segment metadata changed mid-message");
        }
        if let Some(existing) = &assembly.chunks[segment_id] {
            if existing != &chunk {
                self.remove_assembly(&key);
                bail!("remote-control server segment changed when repeated");
            }
        } else {
            if assembly.received_bytes.saturating_add(chunk.len()) > assembly.message_size
                || self.buffered_bytes.saturating_add(chunk.len()) > MAX_BUFFERED_ASSEMBLY_BYTES
            {
                self.remove_assembly(&key);
                bail!("remote-control server segments exceed the reassembly size limit");
            }
            assembly.received_bytes += chunk.len();
            self.buffered_bytes += chunk.len();
            assembly.chunks[segment_id] = Some(chunk);
        }
        if assembly.chunks.iter().any(Option::is_none) {
            return Ok(None);
        }
        let assembly = self.assemblies.remove(&key).expect("assembly exists");
        self.buffered_bytes = self.buffered_bytes.saturating_sub(assembly.received_bytes);
        let bytes: Vec<u8> = assembly.chunks.into_iter().flatten().flatten().collect();
        if bytes.len() != assembly.message_size {
            bail!("reassembled remote-control message has the wrong size");
        }
        let message: Value =
            serde_json::from_slice(&bytes).context("reassembled app-server message is invalid")?;
        if !message.is_object() {
            bail!("reassembled app-server message is not an object");
        }
        let mut complete = Map::new();
        for field in [
            "client_id",
            "seq_id",
            "stream_id",
            "cursor",
            "env_id",
            "skip_history",
        ] {
            if let Some(value) = assembly.first.get(field) {
                complete.insert(field.into(), value.clone());
            }
        }
        complete.insert("type".into(), Value::String("server_message".into()));
        complete.insert("message".into(), message);
        Ok(Some(Value::Object(complete)))
    }

    fn remove_assembly(&mut self, key: &str) {
        if let Some(assembly) = self.assemblies.remove(key) {
            self.buffered_bytes = self.buffered_bytes.saturating_sub(assembly.received_bytes);
        }
    }
}

fn parse_text_message(message: Message) -> Result<Value> {
    let bytes = match message {
        Message::Text(text) => text.as_bytes().to_vec(),
        Message::Binary(bytes) => bytes.to_vec(),
        _ => bail!("remote-control websocket sent a non-data challenge frame"),
    };
    serde_json::from_slice(&bytes).context("remote-control websocket frame is not JSON")
}

pub fn server_envelope_targets_active_stream(
    envelope: &Value,
    client_id: &str,
    environment_id: &str,
    stream_id: &str,
) -> Result<bool> {
    let object = envelope
        .as_object()
        .context("remote-control server envelope is not an object")?;
    if string_field(object, "client_id")? != client_id
        || string_field(object, "env_id")? != environment_id
    {
        bail!("remote-control server envelope targets a different client or host");
    }
    Ok(string_field(object, "stream_id")? == stream_id)
}

fn string_field<'a>(object: &'a Map<String, Value>, name: &str) -> Result<&'a str> {
    object
        .get(name)
        .and_then(Value::as_str)
        .with_context(|| format!("relay envelope has no {name}"))
}

fn usize_field(object: &Map<String, Value>, name: &str) -> Result<usize> {
    object
        .get(name)
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .with_context(|| format!("relay envelope has no valid {name}"))
}
