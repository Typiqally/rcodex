use std::path::Path;

use anyhow::{Context, Result, bail};

use crate::{
    api::RelayApi,
    device_key::{
        create_os_protected_device_key, delete_os_protected_device_key,
        sign_with_os_protected_device_key,
    },
    oauth::request_step_up_token,
    protocol::{EnrollmentRecord, build_enrollment_signing_payload, device_identity_hash},
    relay::{
        RemoteControlSession, build_enroll_finish_body, build_refresh_finish_body,
        device_key_proof, validate_remote_session,
    },
    state::{ControllerState, load_controller_state, save_controller_state},
};

pub async fn ensure_session(
    api: &RelayApi,
    state_path: &Path,
) -> Result<(ControllerState, RemoteControlSession)> {
    if state_path.exists() {
        let state = load_controller_state(state_path)?;
        let session = refresh_session(api, &state.enrollment).await?;
        return Ok((state, session));
    }
    enroll(api, state_path).await
}

pub async fn enroll(
    api: &RelayApi,
    state_path: &Path,
) -> Result<(ControllerState, RemoteControlSession)> {
    if state_path.exists() {
        bail!("rcodex is already enrolled; remove its state explicitly before re-enrolling");
    }
    let auth = api.auth().await?;
    let start = api.enroll_start().await?;
    if !auth.matches_relay_account_user_id(&start.account_user_id)
        || start.device_key_challenge.account_user_id != start.account_user_id
        || start.device_key_challenge.client_id != start.client_id
    {
        bail!("remote-control enrollment start does not match the current ChatGPT account");
    }
    if start.device_key_challenge.challenge_expires_at <= chrono::Utc::now().timestamp() {
        bail!("remote-control enrollment challenge is already expired");
    }

    let identity = create_os_protected_device_key()?;
    let key_id = identity.key_id.clone();
    let result = async {
        let enrollment = EnrollmentRecord {
            account_user_id: start.account_user_id,
            algorithm: identity.algorithm,
            client_id: start.client_id,
            key_id: identity.key_id,
            protection_class: identity.protection_class,
            public_key_spki_der_base64: identity.public_key_spki_der_base64,
        };
        let signed_payload = build_enrollment_signing_payload(
            &enrollment,
            &start.device_key_challenge,
            "/codex/remote/control/client/enroll/finish",
            false,
        )?;
        let signature = sign_with_os_protected_device_key(&enrollment.key_id, &signed_payload)?;
        let proof = device_key_proof(
            &start.device_key_challenge.challenge_token,
            &enrollment.key_id,
            &signed_payload,
            &signature,
        );
        let step_up_token =
            request_step_up_token(api.http_client(), auth.account_id(), auth.account_user_id())
                .await?;
        let session = api
            .enroll_finish(build_enroll_finish_body(&enrollment, &step_up_token, proof))
            .await?;
        validate_remote_session(&enrollment, &session, chrono::Utc::now().timestamp())?;
        let state = ControllerState { enrollment };
        save_controller_state(state_path, &state)?;
        Ok::<_, anyhow::Error>((state, session))
    }
    .await;
    if result.is_err() {
        let _ = delete_os_protected_device_key(&key_id);
    }
    result
}

pub async fn refresh_session(
    api: &RelayApi,
    enrollment: &EnrollmentRecord,
) -> Result<RemoteControlSession> {
    let start = api.refresh_start(enrollment).await?;
    if start.account_user_id != enrollment.account_user_id
        || start.client_id != enrollment.client_id
        || start.device_key_challenge.account_user_id != enrollment.account_user_id
        || start.device_key_challenge.client_id != enrollment.client_id
    {
        bail!("remote-control refresh challenge does not match the local enrollment");
    }
    if start.device_key_challenge.device_identity_hash.as_deref()
        != Some(device_identity_hash(enrollment).as_str())
    {
        bail!("remote-control refresh challenge has the wrong device identity");
    }
    if start.device_key_challenge.challenge_expires_at <= chrono::Utc::now().timestamp() {
        bail!("remote-control refresh challenge is already expired");
    }
    let signed_payload = build_enrollment_signing_payload(
        enrollment,
        &start.device_key_challenge,
        "/codex/remote/control/client/refresh/finish",
        true,
    )?;
    let signature = sign_with_os_protected_device_key(&enrollment.key_id, &signed_payload)
        .context("authorize remote-control session refresh")?;
    let proof = device_key_proof(
        &start.device_key_challenge.challenge_token,
        &enrollment.key_id,
        &signed_payload,
        &signature,
    );
    let session = api
        .refresh_finish(build_refresh_finish_body(enrollment, proof))
        .await?;
    validate_remote_session(enrollment, &session, chrono::Utc::now().timestamp())?;
    Ok(session)
}
