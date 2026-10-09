//! Bounded machine protocol for isolating relay credentials from controller UIs.

use std::{
    collections::HashSet,
    fmt::{Debug, Formatter},
};

use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;

use crate::api::RemoteEnvironment;

pub const BROKER_PROTOCOL_VERSION: u32 = 1;
pub const MAX_BROKER_FRAME_BYTES: usize = 16 * 1024;
const MAX_HOST_ID_BYTES: usize = 128;
const MAX_HOST_LABEL_CHARS: usize = 256;
const MAX_METADATA_CHARS: usize = 128;

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum BrokerRequest {
    Handshake {
        version: u32,
        id: u64,
        #[serde(rename = "minimumVersion")]
        minimum_version: u32,
        #[serde(rename = "maximumVersion")]
        maximum_version: u32,
    },
    Pair {
        version: u32,
        id: u64,
        #[serde(rename = "pairingCode")]
        pairing_code: PairingCode,
    },
    ListHosts {
        version: u32,
        id: u64,
    },
    OpenAppServer {
        version: u32,
        id: u64,
        #[serde(rename = "environmentId")]
        environment_id: String,
    },
}

impl BrokerRequest {
    pub const fn id(&self) -> u64 {
        match self {
            Self::Handshake { id, .. }
            | Self::Pair { id, .. }
            | Self::ListHosts { id, .. }
            | Self::OpenAppServer { id, .. } => *id,
        }
    }

    pub fn pairing_code(&self) -> Option<&str> {
        match self {
            Self::Pair { pairing_code, .. } => Some(pairing_code.as_str()),
            _ => None,
        }
    }
}

impl Debug for BrokerRequest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Handshake {
                version,
                id,
                minimum_version,
                maximum_version,
            } => formatter
                .debug_struct("Handshake")
                .field("version", version)
                .field("id", id)
                .field("minimum_version", minimum_version)
                .field("maximum_version", maximum_version)
                .finish(),
            Self::Pair { version, id, .. } => formatter
                .debug_struct("Pair")
                .field("version", version)
                .field("id", id)
                .field("pairing_code", &"<redacted>")
                .finish(),
            Self::ListHosts { version, id } => formatter
                .debug_struct("ListHosts")
                .field("version", version)
                .field("id", id)
                .finish(),
            Self::OpenAppServer {
                version,
                id,
                environment_id,
            } => formatter
                .debug_struct("OpenAppServer")
                .field("version", version)
                .field("id", id)
                .field("environment_id", environment_id)
                .finish(),
        }
    }
}

pub struct PairingCode(Vec<u8>);

impl PairingCode {
    pub fn new(value: &str) -> Result<Self, BrokerProtocolError> {
        let mut compact = Vec::with_capacity(8);
        for byte in value.bytes() {
            if byte.is_ascii_whitespace() || byte == b'-' {
                continue;
            }
            if !byte.is_ascii_alphanumeric() {
                compact.fill(0);
                return Err(BrokerProtocolError::InvalidPairingCode);
            }
            compact.push(byte.to_ascii_uppercase());
        }
        if compact.len() != 8 {
            compact.fill(0);
            return Err(BrokerProtocolError::InvalidPairingCode);
        }
        let mut normalized = Vec::with_capacity(9);
        normalized.extend_from_slice(&compact[..4]);
        normalized.push(b'-');
        normalized.extend_from_slice(&compact[4..]);
        compact.fill(0);
        Ok(Self(normalized))
    }

    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.0).expect("pairing codes are normalized ASCII")
    }
}

impl Debug for PairingCode {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("<redacted>")
    }
}

impl Drop for PairingCode {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

impl<'de> Deserialize<'de> for PairingCode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        let result = Self::new(&value).map_err(serde::de::Error::custom);
        let mut bytes = value.into_bytes();
        bytes.fill(0);
        result
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BrokerCapability {
    Pair,
    ListHosts,
    OpenAppServer,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BrokerErrorCode {
    AuthenticationRequired,
    EnrollmentRequired,
    InvalidRequest,
    IncompatibleVersion,
    HostNotFound,
    HostOffline,
    RelayUnavailable,
    Internal,
}

#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum BrokerResponse {
    Handshake {
        version: u32,
        id: u64,
        #[serde(rename = "brokerVersion")]
        broker_version: &'static str,
        capabilities: Vec<BrokerCapability>,
    },
    Hosts {
        version: u32,
        id: u64,
        hosts: Vec<BrokerHost>,
    },
    Paired {
        version: u32,
        id: u64,
        hosts: Vec<BrokerHost>,
    },
    Ready {
        version: u32,
        id: u64,
        #[serde(rename = "environmentId")]
        environment_id: String,
    },
    Error {
        version: u32,
        id: u64,
        code: BrokerErrorCode,
    },
}

impl BrokerResponse {
    pub fn handshake(id: u64) -> Self {
        Self::Handshake {
            version: BROKER_PROTOCOL_VERSION,
            id,
            broker_version: env!("CARGO_PKG_VERSION"),
            capabilities: vec![
                BrokerCapability::Pair,
                BrokerCapability::ListHosts,
                BrokerCapability::OpenAppServer,
            ],
        }
    }

    pub const fn error(id: u64, code: BrokerErrorCode) -> Self {
        Self::Error {
            version: BROKER_PROTOCOL_VERSION,
            id,
            code,
        }
    }

    pub fn hosts(id: u64, hosts: Vec<BrokerHost>) -> Self {
        Self::Hosts {
            version: BROKER_PROTOCOL_VERSION,
            id,
            hosts,
        }
    }

    pub fn paired(id: u64, hosts: Vec<BrokerHost>) -> Self {
        Self::Paired {
            version: BROKER_PROTOCOL_VERSION,
            id,
            hosts,
        }
    }

    pub fn ready(id: u64, environment_id: String) -> Self {
        Self::Ready {
            version: BROKER_PROTOCOL_VERSION,
            id,
            environment_id,
        }
    }
}

#[derive(Debug)]
pub enum BrokerAction {
    Respond(BrokerResponse),
    Pair { id: u64, pairing_code: PairingCode },
    ListHosts { id: u64 },
    OpenAppServer { id: u64, environment_id: String },
}

#[derive(Default)]
pub struct BrokerSession {
    initialized: bool,
    request_ids: HashSet<u64>,
}

impl BrokerSession {
    pub fn accept(&mut self, request: BrokerRequest) -> Result<BrokerAction, BrokerErrorCode> {
        let id = request.id();
        if self.request_ids.contains(&id) {
            return Err(BrokerErrorCode::InvalidRequest);
        }
        match request {
            BrokerRequest::Handshake { .. } if !self.initialized => {
                self.initialized = true;
                self.request_ids.insert(id);
                Ok(BrokerAction::Respond(BrokerResponse::handshake(id)))
            }
            BrokerRequest::Handshake { .. } => Err(BrokerErrorCode::InvalidRequest),
            BrokerRequest::Pair { pairing_code, .. } if self.initialized => {
                self.request_ids.insert(id);
                Ok(BrokerAction::Pair { id, pairing_code })
            }
            BrokerRequest::ListHosts { .. } if self.initialized => {
                self.request_ids.insert(id);
                Ok(BrokerAction::ListHosts { id })
            }
            BrokerRequest::OpenAppServer { environment_id, .. } if self.initialized => {
                self.request_ids.insert(id);
                Ok(BrokerAction::OpenAppServer { id, environment_id })
            }
            BrokerRequest::Pair { .. }
            | BrokerRequest::ListHosts { .. }
            | BrokerRequest::OpenAppServer { .. } => Err(BrokerErrorCode::InvalidRequest),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrokerHost {
    pub id: String,
    pub label: String,
    pub online: bool,
    pub busy: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_server_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arch: Option<String>,
}

impl TryFrom<RemoteEnvironment> for BrokerHost {
    type Error = BrokerProtocolError;

    fn try_from(environment: RemoteEnvironment) -> Result<Self, Self::Error> {
        let label = environment.display_name().to_owned();
        validate_text(&environment.env_id, MAX_HOST_ID_BYTES, false)?;
        validate_text(&label, MAX_HOST_LABEL_CHARS, true)?;
        validate_optional_text(
            environment.app_server_version.as_deref(),
            MAX_METADATA_CHARS,
        )?;
        validate_optional_text(environment.os.as_deref(), MAX_METADATA_CHARS)?;
        validate_optional_text(environment.arch.as_deref(), MAX_METADATA_CHARS)?;
        Ok(Self {
            id: environment.env_id,
            label,
            online: environment.online,
            busy: environment.busy,
            app_server_version: environment.app_server_version,
            os: environment.os,
            arch: environment.arch,
        })
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum BrokerProtocolError {
    #[error("broker frame is empty")]
    EmptyFrame,
    #[error("broker frame exceeds the safety limit")]
    FrameTooLarge,
    #[error("broker frame is malformed")]
    MalformedFrame,
    #[error("broker protocol version is incompatible")]
    IncompatibleVersion,
    #[error("pairing code must contain exactly eight letters or digits")]
    InvalidPairingCode,
    #[error("relay host metadata is invalid")]
    InvalidHostMetadata,
}

pub fn decode_request(bytes: &[u8]) -> Result<BrokerRequest, BrokerProtocolError> {
    if bytes.is_empty() {
        return Err(BrokerProtocolError::EmptyFrame);
    }
    if bytes.len() > MAX_BROKER_FRAME_BYTES {
        return Err(BrokerProtocolError::FrameTooLarge);
    }
    let request: BrokerRequest =
        serde_json::from_slice(bytes).map_err(|_| BrokerProtocolError::MalformedFrame)?;
    match &request {
        BrokerRequest::Handshake {
            version,
            minimum_version,
            maximum_version,
            ..
        } if *version == BROKER_PROTOCOL_VERSION
            && *minimum_version <= BROKER_PROTOCOL_VERSION
            && *maximum_version >= BROKER_PROTOCOL_VERSION => {}
        BrokerRequest::Pair { version, .. }
        | BrokerRequest::ListHosts { version, .. }
        | BrokerRequest::OpenAppServer { version, .. }
            if *version == BROKER_PROTOCOL_VERSION => {}
        _ => return Err(BrokerProtocolError::IncompatibleVersion),
    }
    if let BrokerRequest::OpenAppServer { environment_id, .. } = &request {
        validate_text(environment_id, MAX_HOST_ID_BYTES, false)?;
    }
    Ok(request)
}

fn validate_optional_text(
    value: Option<&str>,
    maximum_chars: usize,
) -> Result<(), BrokerProtocolError> {
    if let Some(value) = value {
        validate_text(value, maximum_chars, true)?;
    }
    Ok(())
}

fn validate_text(
    value: &str,
    maximum: usize,
    count_chars: bool,
) -> Result<(), BrokerProtocolError> {
    let length = if count_chars {
        value.chars().count()
    } else {
        value.len()
    };
    if value.trim().is_empty()
        || length > maximum
        || value.chars().any(|character| character.is_control())
    {
        return Err(BrokerProtocolError::InvalidHostMetadata);
    }
    Ok(())
}
