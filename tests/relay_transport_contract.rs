use base64::{Engine as _, engine::general_purpose::STANDARD};
use rcodex::transport::{
    ServerMessageReassembler, relay_websocket_url, segment_client_message,
    server_envelope_targets_active_stream,
};
use serde_json::json;

#[test]
fn relay_url_uses_websocket_scheme() {
    assert_eq!(
        relay_websocket_url().unwrap().as_str(),
        "wss://chatgpt.com/backend-api/codex/remote/control/client"
    );
}

#[test]
fn oversized_client_messages_are_split_without_changing_sequence_identity() {
    let envelope = json!({
        "type": "client_message",
        "client_id": "client-id",
        "seq_id": 7,
        "stream_id": "stream-id",
        "env_id": "env-id",
        "skip_history": false,
        "message": {"method": "large", "params": {"text": "x".repeat(180_000)}}
    });

    let segments = segment_client_message(&envelope).unwrap();

    assert!(segments.len() > 1);
    for (index, segment) in segments.iter().enumerate() {
        assert_eq!(segment["type"], "client_message_chunk");
        assert_eq!(segment["seq_id"], 7);
        assert_eq!(segment["segment_id"], index);
        assert_eq!(segment["segment_count"], segments.len());
        assert!(serde_json::to_vec(segment).unwrap().len() <= 150 * 1024);
    }
}

#[test]
fn server_chunks_reassemble_to_the_original_message() {
    let message = json!({"id": 1, "result": {"serverInfo": {"name": "codex"}}});
    let bytes = serde_json::to_vec(&message).unwrap();
    let midpoint = bytes.len() / 2;
    let chunks = [&bytes[..midpoint], &bytes[midpoint..]];
    let mut reassembler = ServerMessageReassembler::default();

    for (index, chunk) in chunks.iter().enumerate() {
        let observed = reassembler
            .observe(&json!({
                "type": "server_message_chunk",
                "client_id": "client-id",
                "seq_id": 1,
                "stream_id": "stream-id",
                "env_id": "env-id",
                "cursor": "cursor",
                "segment_id": index,
                "segment_count": chunks.len(),
                "message_size_bytes": bytes.len(),
                "message_chunk_base64": STANDARD.encode(chunk),
            }))
            .unwrap();
        if index == 0 {
            assert!(observed.is_none());
        } else {
            assert_eq!(observed.unwrap()["message"], message);
        }
    }
}

#[test]
fn server_reassembly_rejects_messages_over_the_safe_limit() {
    let mut reassembler = ServerMessageReassembler::default();
    let result = reassembler.observe(&json!({
        "type": "server_message_chunk",
        "client_id": "client-id",
        "seq_id": 1,
        "stream_id": "stream-id",
        "env_id": "env-id",
        "segment_id": 0,
        "segment_count": 2,
        "message_size_bytes": 64 * 1024 * 1024 + 1,
        "message_chunk_base64": STANDARD.encode(b"{")
    }));

    assert!(result.is_err());
}

#[test]
fn server_reassembly_caps_concurrent_incomplete_messages() {
    let mut reassembler = ServerMessageReassembler::default();

    for sequence in 1..=8 {
        assert!(
            reassembler
                .observe(&json!({
                    "type": "server_message_chunk",
                    "client_id": "client-id",
                    "seq_id": sequence,
                    "stream_id": "stream-id",
                    "env_id": "env-id",
                    "segment_id": 0,
                    "segment_count": 2,
                    "message_size_bytes": 2,
                    "message_chunk_base64": STANDARD.encode(b"{")
                }))
                .unwrap()
                .is_none()
        );
    }

    let ninth = reassembler.observe(&json!({
        "type": "server_message_chunk",
        "client_id": "client-id",
        "seq_id": 9,
        "stream_id": "stream-id",
        "env_id": "env-id",
        "segment_id": 0,
        "segment_count": 2,
        "message_size_bytes": 2,
        "message_chunk_base64": STANDARD.encode(b"{")
    }));

    assert!(ninth.is_err());
}

#[test]
fn delayed_frames_from_an_old_stream_are_ignored_safely() {
    let stale = json!({
        "client_id": "client-id",
        "env_id": "env-id",
        "stream_id": "old-stream",
    });
    assert!(
        !server_envelope_targets_active_stream(&stale, "client-id", "env-id", "active-stream",)
            .unwrap()
    );

    let active = json!({
        "client_id": "client-id",
        "env_id": "env-id",
        "stream_id": "active-stream",
    });
    assert!(
        server_envelope_targets_active_stream(&active, "client-id", "env-id", "active-stream",)
            .unwrap()
    );

    let wrong_host = json!({
        "client_id": "client-id",
        "env_id": "other-env",
        "stream_id": "active-stream",
    });
    assert!(
        server_envelope_targets_active_stream(&wrong_host, "client-id", "env-id", "active-stream",)
            .is_err()
    );
}
