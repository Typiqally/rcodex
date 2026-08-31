use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

const P256_SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceKeyIdentity {
    pub algorithm: String,
    pub key_id: String,
    pub protection_class: String,
    pub public_key_spki_der_base64: String,
}

pub fn p256_x963_to_spki_der(point: &[u8]) -> Result<Vec<u8>> {
    if point.len() != 65 || point.first() != Some(&0x04) {
        bail!("expected a 65-byte uncompressed P-256 public key");
    }
    let mut der = Vec::with_capacity(P256_SPKI_PREFIX.len() + point.len());
    der.extend_from_slice(&P256_SPKI_PREFIX);
    der.extend_from_slice(point);
    Ok(der)
}

#[cfg(target_os = "macos")]
mod macos {
    use anyhow::{Context, Result, bail};
    use core_foundation::{base::TCFType, string::CFString};
    use core_foundation_sys::{
        array::{CFArrayCreate, CFArrayRef, kCFTypeArrayCallBacks},
        base::{CFRelease, CFTypeRef, OSStatus, kCFAllocatorDefault},
        string::CFStringRef,
    };
    use security_framework::{
        base::Error as SecurityError,
        item::{ItemSearchOptions, KeyClass, Reference, SearchResult},
        key::{Algorithm, SecKey},
    };
    use security_framework_sys::base::{
        SecAccessRef, SecKeyRef, SecKeychainRef, errSecItemNotFound, errSecSuccess,
    };
    use std::os::raw::{c_char, c_void};

    use super::{DeviceKeyIdentity, p256_x963_to_spki_der};
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

    #[link(name = "Security", kind = "framework")]
    unsafe extern "C" {
        fn SecTrustedApplicationCreateFromPath(
            path: *const c_char,
            application: *mut CFTypeRef,
        ) -> OSStatus;
        fn SecAccessCreate(
            descriptor: CFStringRef,
            trusted_list: CFArrayRef,
            access: *mut SecAccessRef,
        ) -> OSStatus;
        fn SecKeyCreatePair(
            keychain_ref: SecKeychainRef,
            algorithm: u32,
            key_size_in_bits: u32,
            context_handle: usize,
            public_key_usage: u32,
            public_key_attributes: u32,
            private_key_usage: u32,
            private_key_attributes: u32,
            initial_access: SecAccessRef,
            public_key: *mut SecKeyRef,
            private_key: *mut SecKeyRef,
        ) -> OSStatus;
    }

    const CSSM_ALGID_ECDSA: u32 = 73;
    const CSSM_KEYUSE_SIGN: u32 = 0x0000_0004;
    const CSSM_KEYUSE_VERIFY: u32 = 0x0000_0008;
    const CSSM_KEYATTR_PERMANENT: u32 = 0x0000_0001;
    const CSSM_KEYATTR_SENSITIVE: u32 = 0x0000_0008;
    const CSSM_KEYATTR_EXTRACTABLE: u32 = 0x0000_0020;

    fn prompt_free_access_for_current_binary() -> Result<SecAccessRef> {
        let mut trusted_application: CFTypeRef = std::ptr::null();
        let trusted_status = unsafe {
            SecTrustedApplicationCreateFromPath(std::ptr::null(), &mut trusted_application)
        };
        if trusted_status != errSecSuccess || trusted_application.is_null() {
            return Err(SecurityError::from_code(trusted_status))
                .context("trust the current rcodex binary for Keychain signing");
        }

        let trusted_values = [trusted_application.cast::<c_void>()];
        let trusted_list = unsafe {
            CFArrayCreate(
                kCFAllocatorDefault,
                trusted_values.as_ptr(),
                trusted_values.len() as isize,
                &kCFTypeArrayCallBacks,
            )
        };
        if trusted_list.is_null() {
            unsafe { CFRelease(trusted_application) };
            bail!("create rcodex Keychain trusted-application list");
        }

        let descriptor = CFString::new("rcodex remote-control signing key");
        let mut access: SecAccessRef = std::ptr::null_mut();
        let access_status =
            unsafe { SecAccessCreate(descriptor.as_concrete_TypeRef(), trusted_list, &mut access) };
        unsafe {
            CFRelease(trusted_list.cast());
            CFRelease(trusted_application);
        }
        if access_status != errSecSuccess || access.is_null() {
            return Err(SecurityError::from_code(access_status))
                .context("create prompt-free rcodex Keychain access policy");
        }
        Ok(access)
    }

    fn application_label(key_id: &str) -> Result<Vec<u8>> {
        let encoded = key_id
            .strip_prefix("rcodex_osn_")
            .context("rcodex device key ID has an unexpected format")?;
        let label = URL_SAFE_NO_PAD
            .decode(encoded)
            .context("rcodex device key ID is not base64url")?;
        if label.len() != 20 {
            bail!("rcodex device key ID has an invalid application label");
        }
        Ok(label)
    }

    fn find_private_key(key_id: &str) -> Result<SecKey> {
        let label = application_label(key_id)?;
        let results = ItemSearchOptions::new()
            .key_class(KeyClass::private())
            .application_label(&label)
            .load_refs(true)
            .limit(1)
            .search()
            .with_context(|| format!("find rcodex device key {key_id}"))?;
        match results.into_iter().next() {
            Some(SearchResult::Ref(Reference::Key(key))) => Ok(key),
            Some(_) => bail!("keychain returned an unexpected item for rcodex key {key_id}"),
            None => bail!("rcodex device key {key_id} was not found in the login keychain"),
        }
    }

    pub fn create() -> Result<DeviceKeyIdentity> {
        let access = prompt_free_access_for_current_binary()?;
        let mut public_ref: SecKeyRef = std::ptr::null_mut();
        let mut private_ref: SecKeyRef = std::ptr::null_mut();
        let status = unsafe {
            SecKeyCreatePair(
                std::ptr::null_mut(),
                CSSM_ALGID_ECDSA,
                256,
                0,
                CSSM_KEYUSE_VERIFY,
                CSSM_KEYATTR_PERMANENT | CSSM_KEYATTR_EXTRACTABLE,
                CSSM_KEYUSE_SIGN,
                CSSM_KEYATTR_PERMANENT | CSSM_KEYATTR_SENSITIVE,
                access,
                &mut public_ref,
                &mut private_ref,
            )
        };
        unsafe { CFRelease(access.cast()) };
        if status != errSecSuccess {
            return Err(SecurityError::from_code(status))
                .context("create non-exportable P-256 key in the macOS login Keychain");
        }
        if public_ref.is_null() || private_ref.is_null() {
            bail!("Security.framework created an incomplete P-256 key pair");
        }
        let public_key = unsafe { SecKey::wrap_under_create_rule(public_ref) };
        let private_key = unsafe { SecKey::wrap_under_create_rule(private_ref) };
        if let Some(exported) = private_key.external_representation() {
            let exported_len = exported.len();
            let _ = private_key.delete();
            let _ = public_key.delete();
            bail!(
                "Security.framework created an exportable private key ({exported_len} bytes); refusing enrollment"
            );
        }

        let label = private_key
            .application_label()
            .context("read rcodex device key application label")?;
        let key_id = format!("rcodex_osn_{}", URL_SAFE_NO_PAD.encode(label));
        let public_x963 = public_key
            .external_representation()
            .map(|data| data.to_vec())
            .context("export public half of rcodex device key")?;
        let public_key_spki_der_base64 =
            base64::engine::general_purpose::STANDARD.encode(p256_x963_to_spki_der(&public_x963)?);

        Ok(DeviceKeyIdentity {
            algorithm: "ecdsa_p256_sha256".into(),
            key_id,
            protection_class: "os_protected_nonextractable".into(),
            public_key_spki_der_base64,
        })
    }

    pub fn sign(key_id: &str, payload: &[u8]) -> Result<Vec<u8>> {
        find_private_key(key_id)?
            .create_signature(Algorithm::ECDSASignatureMessageX962SHA256, payload)
            .map_err(|error| anyhow::anyhow!("sign with rcodex device key {key_id}: {error:?}"))
    }

    pub fn delete(key_id: &str) -> Result<()> {
        let label = application_label(key_id)?;
        for key_class in [KeyClass::private(), KeyClass::public()] {
            match ItemSearchOptions::new()
                .key_class(key_class)
                .application_label(&label)
                .delete()
            {
                Ok(()) => {}
                Err(error) if error.code() == errSecItemNotFound => {}
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("delete rcodex device key {key_id}"));
                }
            }
        }
        Ok(())
    }
}

#[cfg(target_os = "macos")]
pub fn create_os_protected_device_key() -> Result<DeviceKeyIdentity> {
    macos::create()
}

#[cfg(not(target_os = "macos"))]
pub fn create_os_protected_device_key() -> Result<DeviceKeyIdentity> {
    bail!("rcodex device keys currently require macOS Security.framework")
}

#[cfg(target_os = "macos")]
pub fn sign_with_os_protected_device_key(key_id: &str, payload: &[u8]) -> Result<Vec<u8>> {
    macos::sign(key_id, payload)
}

#[cfg(not(target_os = "macos"))]
pub fn sign_with_os_protected_device_key(_key_id: &str, _payload: &[u8]) -> Result<Vec<u8>> {
    bail!("rcodex device keys currently require macOS Security.framework")
}

#[cfg(target_os = "macos")]
pub fn delete_os_protected_device_key(key_id: &str) -> Result<()> {
    macos::delete(key_id)
}

#[cfg(not(target_os = "macos"))]
pub fn delete_os_protected_device_key(_key_id: &str) -> Result<()> {
    bail!("rcodex device keys currently require macOS Security.framework")
}
