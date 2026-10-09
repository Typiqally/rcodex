use std::process::Command;

use rcodex::broker::{
    BrokerAction, BrokerErrorCode, BrokerResponse, BrokerSession, decode_request,
};
use serde_json::json;

#[test]
fn broker_cli_is_an_explicit_machine_only_subcommand() {
    let output = Command::new(env!("CARGO_BIN_EXE_rcodex"))
        .args(["broker", "--help"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("bounded JSONL"));
    assert!(!stdout.contains("auth.json"));
}

#[test]
fn broker_session_requires_a_compatible_handshake_before_operations() {
    let mut session = BrokerSession::default();
    let pair =
        decode_request(br#"{"version":1,"id":2,"type":"pair","pairingCode":"ABCD-EFGH"}"#).unwrap();

    assert_eq!(
        session.accept(pair).unwrap_err(),
        BrokerErrorCode::InvalidRequest
    );

    let handshake = decode_request(
        br#"{"version":1,"id":1,"type":"handshake","minimumVersion":1,"maximumVersion":1}"#,
    )
    .unwrap();
    let BrokerAction::Respond(response) = session.accept(handshake).unwrap() else {
        panic!("handshake did not produce a response");
    };
    assert!(matches!(response, BrokerResponse::Handshake { id: 1, .. }));
}

#[test]
fn initialized_broker_dispatches_pair_list_and_open_without_exposing_pairing_code() {
    let mut session = BrokerSession::default();
    let handshake = decode_request(
        br#"{"version":1,"id":1,"type":"handshake","minimumVersion":1,"maximumVersion":1}"#,
    )
    .unwrap();
    session.accept(handshake).unwrap();

    let pair =
        decode_request(br#"{"version":1,"id":2,"type":"pair","pairingCode":"ABCD-EFGH"}"#).unwrap();
    let pair = session.accept(pair).unwrap();
    assert!(matches!(pair, BrokerAction::Pair { id: 2, .. }));
    assert!(!format!("{pair:?}").contains("ABCD-EFGH"));

    let list = decode_request(br#"{"version":1,"id":3,"type":"list_hosts"}"#).unwrap();
    assert!(matches!(
        session.accept(list).unwrap(),
        BrokerAction::ListHosts { id: 3 }
    ));

    let open = decode_request(
        br#"{"version":1,"id":4,"type":"open_app_server","environmentId":"environment-1"}"#,
    )
    .unwrap();
    assert!(matches!(
        session.accept(open).unwrap(),
        BrokerAction::OpenAppServer {
            id: 4,
            environment_id,
        } if environment_id == "environment-1"
    ));
}

#[test]
fn broker_result_builders_emit_only_sanitized_public_metadata() {
    let response = BrokerResponse::paired(8, Vec::new());
    assert_eq!(
        serde_json::to_value(response).unwrap(),
        json!({"version": 1, "id": 8, "type": "paired", "hosts": []})
    );
    assert_eq!(
        serde_json::to_value(BrokerResponse::ready(9, "environment-1".into())).unwrap(),
        json!({
            "version": 1,
            "id": 9,
            "type": "ready",
            "environmentId": "environment-1"
        })
    );
}

#[test]
fn broker_request_ids_can_be_reused_only_after_a_new_process() {
    let mut session = BrokerSession::default();
    let handshake = decode_request(
        br#"{"version":1,"id":1,"type":"handshake","minimumVersion":1,"maximumVersion":1}"#,
    )
    .unwrap();
    session.accept(handshake).unwrap();

    let list = || decode_request(br#"{"version":1,"id":2,"type":"list_hosts"}"#).unwrap();
    session.accept(list()).unwrap();
    assert_eq!(
        session.accept(list()).unwrap_err(),
        BrokerErrorCode::InvalidRequest
    );
}

#[test]
fn broker_rejects_a_second_handshake_in_the_same_process() {
    let mut session = BrokerSession::default();
    let handshake = || {
        decode_request(
            br#"{"version":1,"id":1,"type":"handshake","minimumVersion":1,"maximumVersion":1}"#,
        )
        .unwrap()
    };

    session.accept(handshake()).unwrap();
    assert_eq!(
        session.accept(handshake()).unwrap_err(),
        BrokerErrorCode::InvalidRequest
    );
}
