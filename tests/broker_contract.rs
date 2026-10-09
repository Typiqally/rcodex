use rcodex::{
    api::RemoteEnvironment,
    broker::{
        BROKER_PROTOCOL_VERSION, BrokerErrorCode, BrokerHost, BrokerRequest, BrokerResponse,
        MAX_BROKER_FRAME_BYTES, decode_request,
    },
};
use serde_json::json;

fn environment(id: &str, display_name: &str) -> RemoteEnvironment {
    RemoteEnvironment {
        app_server_version: Some("0.153.0".into()),
        arch: Some("aarch64".into()),
        busy: false,
        client_type: Some("cli".into()),
        display_name: Some(display_name.into()),
        env_id: id.into(),
        host_name: Some("studio.local".into()),
        installation_id: Some("installation-public-id".into()),
        kind: Some("computer".into()),
        last_seen_at: Some("2026-09-01T10:00:00Z".into()),
        name: None,
        online: true,
        os: Some("macos".into()),
    }
}

#[test]
fn broker_handshake_is_versioned_and_advertises_only_implemented_operations() {
    let request = decode_request(
        br#"{"version":1,"id":7,"type":"handshake","minimumVersion":1,"maximumVersion":1}"#,
    )
    .unwrap();

    assert_eq!(BROKER_PROTOCOL_VERSION, 1);
    assert!(matches!(
        request,
        BrokerRequest::Handshake {
            version: 1,
            id: 7,
            minimum_version: 1,
            maximum_version: 1,
        }
    ));
    assert_eq!(
        serde_json::to_value(BrokerResponse::handshake(7)).unwrap(),
        json!({
            "version": 1,
            "id": 7,
            "type": "handshake",
            "brokerVersion": env!("CARGO_PKG_VERSION"),
            "capabilities": ["pair", "list_hosts", "open_app_server"]
        })
    );
}

#[test]
fn pairing_artifacts_are_validated_and_redacted_from_debug_output() {
    let request =
        decode_request(br#"{"version":1,"id":8,"type":"pair","pairingCode":"abcd efgh"}"#).unwrap();

    assert!(matches!(request, BrokerRequest::Pair { id: 8, .. }));
    let debug = format!("{request:?}");
    assert!(!debug.contains("abcd"));
    assert!(!debug.contains("efgh"));
    assert!(debug.contains("<redacted>"));

    assert!(
        decode_request(br#"{"version":1,"id":8,"type":"pair","pairingCode":"too-long-secret"}"#)
            .is_err()
    );
}

#[test]
fn broker_frames_and_unknown_fields_are_rejected_before_dispatch() {
    let oversized = vec![b'x'; MAX_BROKER_FRAME_BYTES + 1];
    assert!(decode_request(&oversized).is_err());
    assert!(
        decode_request(br#"{"version":1,"id":1,"type":"list_hosts","unexpected":true}"#).is_err()
    );
}

#[test]
fn relay_host_metadata_is_bounded_before_crossing_the_broker_boundary() {
    let host = BrokerHost::try_from(environment("environment-1", "Build Studio")).unwrap();
    assert_eq!(
        serde_json::to_value(host).unwrap(),
        json!({
            "id": "environment-1",
            "label": "Build Studio",
            "online": true,
            "busy": false,
            "appServerVersion": "0.153.0",
            "os": "macos",
            "arch": "aarch64"
        })
    );

    assert!(BrokerHost::try_from(environment(&"x".repeat(129), "Build Studio")).is_err());
    assert!(BrokerHost::try_from(environment("environment-1", &"x".repeat(257))).is_err());
    assert!(BrokerHost::try_from(environment("bad\nenvironment", "Build Studio")).is_err());
}

#[test]
fn broker_errors_are_classified_without_forwarding_sensitive_details() {
    let response = BrokerResponse::error(9, BrokerErrorCode::AuthenticationRequired);
    assert_eq!(
        serde_json::to_value(response).unwrap(),
        json!({
            "version": 1,
            "id": 9,
            "type": "error",
            "code": "authentication_required"
        })
    );
}
